import os
import json
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from .models import Scan
from targets.models import Endpoint, Technology
from vulnerabilities.models import Vulnerability

logger = logging.getLogger(__name__)

SCAN_TASK_MAP = {
    'DIRSEARCH': 'scans.tasks.run_dirsearch',
    'HTTPX_TECH': 'scans.tasks.run_httpx_tech',
    'INQL': 'scans.tasks.run_inql',
    'GAU': 'scans.tasks.run_gau',
    'WAYBACKURLS': 'scans.tasks.run_waybackurls',
    'SWAGGER': 'scans.tasks.run_swagger',
    'SOAP_WSDL': 'scans.tasks.run_soap_wsdl',
    'GRPCURL': 'scans.tasks.run_grpcurl',
    'ARJUN': 'fuzzing.tasks.run_arjun',
    'NUCLEI': 'scans.tasks.run_nuclei_vuln_scan',
    'NMAP': 'scans.tasks.run_nmap_scan',
    'SSL_CHECK': 'scans.tasks.run_ssl_check',
    'FULL_WORKFLOW': 'scans.tasks.run_full_workflow',
    'WAPITI': 'scans.tasks.run_wapiti',
}

@shared_task(bind=True)
def run_dirsearch(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_domain = scan.target.domain
    output_file = settings.SCAN_OUTPUT_DIR / f'dirsearch_{scan_id}.json'
    
    command = [
        settings.DIRSEARCH_PATH,
        '-u', f'https://{target_domain}',
        '-e', 'php,html,txt,bak',
        '-i', '200,403',
        '--format=json',
        '-o', str(output_file)
    ]

    try:
        subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if output_file.exists():
            with open(output_file, 'r') as f:
                data = json.load(f)
                if 'results' in data:
                    for res in data['results']:
                        url = res.get('url')
                        status = res.get('status')
                        if url:
                            Endpoint.objects.get_or_create(
                                target=scan.target,
                                url=url,
                                defaults={'status_code': status}
                            )

        scan.status = 'COMPLETED'
        scan.result_file = str(output_file)
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()
        send_alert_for_scan.delay(scan.id)


def send_email_alert(subject, message):
    if not settings.ALERT_EMAIL_ENABLED:
        return
    try:
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg.set_content(message)
        msg['Subject'] = subject
        msg['From'] = settings.ALERT_EMAIL_FROM
        msg['To'] = ', '.join(settings.ALERT_EMAIL_TO)
        with smtplib.SMTP(settings.ALERT_EMAIL_HOST, settings.ALERT_EMAIL_PORT) as server:
            if settings.ALERT_EMAIL_USER:
                server.starttls()
                server.login(settings.ALERT_EMAIL_USER, settings.ALERT_EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception:
        pass


@shared_task(bind=True)
def send_alert_for_scan(self, scan_id):
    from vulnerabilities.models import Vulnerability
    from scans.models import SSLResult

    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return

    threshold = settings.ALERT_SEVERITY_THRESHOLD
    severity_order = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    min_level = severity_order.get(threshold, 2)

    findings = []
    vulns = Vulnerability.objects.filter(target=scan.target, source_tool__icontains=scan.scan_type)
    for v in vulns:
        if severity_order.get(v.severity, 0) >= min_level:
            findings.append(f"[{v.severity}] {v.title} (CVSS: {v.cvss_score or 'N/A'})")

    ssl_results = SSLResult.objects.filter(scan=scan)
    for sr in ssl_results:
        if sr.grade and sr.grade in ['F', 'T']:
            findings.append(f"[CRITICAL] SSL Grade {sr.grade} for {sr.host}:{sr.port}")

    if findings:
        subject = f"[ASMM Alert] {scan.scan_type} on {scan.target.domain} - {len(findings)} findings"
        message = f"Scan ID: {scan.id}\nTarget: {scan.target.domain}\nType: {scan.scan_type}\n\nFindings:\n" + "\n".join(findings)
        send_email_alert(subject, message)

# Nuclei tag groups -- each runs as a separate concurrent subprocess
NUCLEI_TAG_GROUPS = [
    ['cve'],
    ['misconfiguration', 'misconfig'],
    ['exposure', 'default-login'],
]


def _run_nuclei_tag_group(target_url, tags, output_file):
    """Run one Nuclei subprocess for a specific tag group."""
    command = [
        settings.NUCLEI_PATH,
        '-u', target_url,
        '-tags', ','.join(tags),
        '-severity', 'critical,high,medium',
        '-rl', '300',
        '-bs', '50',
        '-c', '100',
        '-timeout', '3',
        '-retries', '1',
        '-duc',
        '-ni',
        '-nc',
        '-json-export', str(output_file),
    ]
    # Explicitly point to the local templates directory
    nuclei_tpl = getattr(settings, 'NUCLEI_TEMPLATES_PATH', None)
    if nuclei_tpl:
        command.extend(['-t', nuclei_tpl])
    try:
        subprocess.run(command, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        logger.warning("Nuclei tag group %s timed out for %s", tags, target_url)
    return output_file.exists()


def _import_nuclei_result_to_faraday(output_file):
    if not getattr(settings, 'FARADAY_AUTO_IMPORT_NUCLEI', True):
        return None
    output_path = Path(output_file)
    if not output_path.exists() or output_path.stat().st_size == 0:
        return None

    pipeline_url = str(getattr(settings, 'FARADAY_PIPELINE_URL', 'http://127.0.0.1:8001')).rstrip('/')
    response = requests.post(
        f'{pipeline_url}/faraday/import-nuclei-file',
        json={'file_path': str(output_path.resolve())},
        timeout=180,
    )
    response.raise_for_status()
    return response.json()


@shared_task(bind=True)
def run_nuclei_vuln_scan(self, scan_id):
    """
    Executes Python vulnerability scanner on the scan target.
    Persists discovered vulnerabilities to DB and exports report to Faraday if configured.
    """
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_domain = scan.target.domain
    target_url = f'https://{target_domain}'

    try:
        from attacksurface.scanner.vulnerability_scanner import run_python_vuln_scanner
        httpx_items = [{"url": target_url, "headers": {}, "status_code": 0}]
        findings = run_python_vuln_scanner(target_domain, httpx_items)

        output_file = settings.SCAN_OUTPUT_DIR / f'nuclei_{scan_id}.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json.dumps(findings, indent=2))

        for item in findings:
            title = item.get('finding') or item.get('vulnerability_id') or 'Vulnerability Discovered'
            severity = str(item.get('severity') or 'MEDIUM').upper()

            Vulnerability.objects.get_or_create(
                target=scan.target,
                title=title,
                defaults={
                    'severity': severity,
                    'description': item.get('finding', ''),
                    'remediation': 'Apply recommended security headers and configuration updates.',
                    'source_tool': 'PythonScanner',
                    'cve_id': item.get('cve', ''),
                    'cwe_id': item.get('cwe', ''),
                    'references': ''
                }
            )

        scan.status = 'COMPLETED'
        scan.result_file = str(output_file)
        try:
            faraday_result = _import_nuclei_result_to_faraday(output_file)
            if faraday_result:
                logger.info("Imported Python scan %s results to Faraday: %s", scan_id, faraday_result)
        except Exception as exc:
            logger.warning("Faraday import failed for Python scan %s: %s", scan_id, exc)
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.save()

        scan.completed_at = timezone.now()
        scan.save()

@shared_task(bind=True)
def run_wappalyzer_scan(self, scan_id):
    """
    Executes technology profiling and registers dependencies/CMS/servers
    """
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_url = f"https://{scan.target.domain}"
    
    try:
        from Wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(target_url)
        results = wappalyzer.analyze_with_versions(webpage)
        
        # Structure of results: {'WordPress': {'versions': ['6.1']}, 'Nginx': {'versions': []}}
        for tech_name, info in results.items():
            versions = info.get('versions', [])
            version = versions[0] if versions else None
            
            # Fetch default category from name logic
            category = 'Web Tech'
            if tech_name.lower() in ['wordpress', 'drupal', 'joomla']:
                category = 'CMS'
            elif tech_name.lower() in ['nginx', 'apache', 'iis']:
                category = 'Web Server'
            elif tech_name.lower() in ['jquery', 'react', 'vue']:
                category = 'JavaScript Library'

            Technology.objects.update_or_create(
                target=scan.target,
                name=tech_name,
                defaults={
                    'version': version,
                    'category': category,
                    'detected_by': 'Wappalyzer'
                }
            )
            
            # Automatically query VulnDB / CVE APIs if a specific version of a component is detected
            if version:
                check_technology_cves(scan.target, tech_name, version)
                
        scan.status = 'COMPLETED'
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()

def fetch_nvd_cvss_score(cve_id):
    """
    Safely queries official NVD National Vulnerability Database API to pull CVSS metrics
    """
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {'User-Agent': 'ASMM-Platform'}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                metrics = vulnerabilities[0].get('cve', {}).get('metrics', {})
                # Try v3.1 first, then v3.0, then v2
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    metric_list = metrics.get(version, [])
                    if metric_list:
                        return metric_list[0].get('cvssData', {}).get('baseScore', None)
    except Exception:
        pass
    return None

def check_technology_cves(target, tech_name, version):
    """
    Integrates completely with NVD API to find known CVE vulnerabilities for detected components/versions
    """
    try:
        keyword = f"{tech_name} {version}"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
        headers = {'User-Agent': 'ASMM-Platform'}
        response = requests.get(url, headers=headers, timeout=5)

        if response.status_code == 200:
            data = response.json()
            for item in data.get('vulnerabilities', [])[:5]:
                cve = item.get('cve', {})
                cve_id = cve.get('id')
                description = cve.get('descriptions', [{}])[0].get('value', 'No description available')

                metrics = cve.get('metrics', {})
                cvss_score = None
                severity = 'MEDIUM'

                for version_key in ['cvssMetricV31', 'cvssMetricV30']:
                    metric_list = metrics.get(version_key, [])
                    if metric_list:
                        cvss_score = metric_list[0].get('cvssData', {}).get('baseScore', None)
                        severity = metric_list[0].get('cvssData', {}).get('baseSeverity', 'MEDIUM')
                        break

                Vulnerability.objects.get_or_create(
                    target=target,
                    title=f"Vulnerable Dependency: {tech_name} {version} ({cve_id})",
                    defaults={
                        'severity': severity.upper(),
                        'description': f"Known vulnerability discovered in detected technology: {description}",
                        'source_tool': 'Wappalyzer CVE Scanner',
                        'cve_id': cve_id,
                        'cvss_score': cvss_score
                    }
                )
    except Exception:
        pass


@shared_task(bind=True)
def run_ssl_check(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_domain = scan.target.domain
    output_file = settings.SCAN_OUTPUT_DIR / f'testssl_{scan_id}.json'
    testssl_path = getattr(settings, 'TESTSSL_PATH', 'testssl.sh')

    testssl_env = {**os.environ, "TESTSSL_INSTALL_DIR": str(Path(testssl_path).resolve().parent)} if testssl_path else None

    command = [
        testssl_path,
        '--jsonfile-pretty', str(output_file),
        target_domain
    ]

    try:
        subprocess.run(command, capture_output=True, text=True, timeout=300, env=testssl_env)

        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if isinstance(data, list):
                host_info = data[0] if data else {}
            else:
                host_info = data

            host = host_info.get('Host', target_domain)
            port = host_info.get('Port', 443)
            grade = host_info.get('grade', None) or host_info.get('Grade', None)
            cert_info = json.dumps({
                k: host_info.get(k) for k in
                ['cert_chain_issues', 'certificate_notBefore', 'certificate_notAfter',
                 'issuer', 'subjectAltNames', 'key_size', 'signature_algo']
                if k in host_info
            }, indent=2)

            protocols = host_info.get('protocols', None) or host_info.get('Protocols', None)
            if protocols is None:
                protocols = json.dumps({
                    k: host_info.get(k) for k in host_info
                    if any(p in k.lower() for p in ['tls', 'ssl', 'proto'])
                }, indent=2)

            vulns = host_info.get('vulnerabilities', None) or host_info.get('Vulnerabilities', None)
            if vulns is None:
                vuln_keys = [k for k in host_info
                            if any(v in k.lower() for v in ['vuln', 'cve', 'weak', 'beast', 'poodle', 'heartbleed', 'freak'])]
                vulns = json.dumps({k: host_info.get(k) for k in vuln_keys}, indent=2) if vuln_keys else None

            cipher = host_info.get('cipher_strength', None) or host_info.get('CipherStrength', None)

            from .models import SSLResult
            SSLResult.objects.create(
                scan=scan,
                target=scan.target,
                host=host,
                port=port,
                grade=grade,
                certificate_info=cert_info,
                protocols=str(protocols) if protocols else None,
                cipher_strength=cipher,
                vulnerabilities=str(vulns) if vulns else None,
                raw_json=json.dumps(host_info, indent=2)
            )

            scan.status = 'COMPLETED'
            scan.result_file = str(output_file)
        else:
            scan.status = 'FAILED'
            scan.result_file = 'testssl.sh did not produce output file'
    except subprocess.TimeoutExpired:
        scan.status = 'FAILED'
        scan.result_file = 'SSL check timed out (300s)'
    except FileNotFoundError:
        scan.status = 'FAILED'
        scan.result_file = f'testssl.sh not found at "{testssl_path}"'
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_nmap_scan(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_domain = scan.target.domain
    output_file = settings.SCAN_OUTPUT_DIR / f'nmap_{scan_id}.xml'

    command = [
        settings.NMAP_PATH,
        '-sC', '-sV', '-oX', str(output_file),
        target_domain
    ]

    try:
        subprocess.run(command, capture_output=True, text=True, timeout=600)

        if output_file.exists():
            import xml.etree.ElementTree as ET
            tree = ET.parse(output_file)
            root = tree.getroot()
            for host in root.findall('host'):
                addr = host.find('address').get('addr')
                for port in host.findall('ports/port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state').get('state')
                    service = port.find('service')
                    service_name = service.get('name', '') if service is not None else ''
                    version = service.get('version', '') if service is not None else ''
                    Endpoint.objects.get_or_create(
                        target=scan.target,
                        url=f'{protocol}://{addr}:{port_id}',
                        defaults={
                            'status_code': 200 if state == 'open' else None,
                            'technology': f'{service_name} {version}'.strip()
                        }
                    )

            scan.status = 'COMPLETED'
            scan.result_file = str(output_file)
        else:
            scan.status = 'FAILED'
            scan.result_file = 'Nmap did not produce output file'
    except subprocess.TimeoutExpired:
        scan.status = 'FAILED'
        scan.result_file = 'Nmap scan timed out (600s)'
    except FileNotFoundError:
        scan.status = 'FAILED'
        scan.result_file = f'Nmap not found at "{settings.NMAP_PATH}"'
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_httpx_tech(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_url = f"https://{scan.target.domain}"
    output_file = settings.SCAN_OUTPUT_DIR / f'httpx_{scan_id}.json'

    command = [
        settings.HTTPX_PATH,
        '-u', target_url,
        '-tech-detect',
        '-json',
        '-o', str(output_file)
    ]

    try:
        subprocess.run(command, capture_output=True, text=True, timeout=300)

        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    data = json.loads(line)
                    techs = data.get('tech', [])
                    for tech in techs:
                        Technology.objects.update_or_create(
                            target=scan.target,
                            name=tech,
                            defaults={
                                'category': 'Detected by httpx',
                                'detected_by': 'httpx'
                            }
                        )

            scan.status = 'COMPLETED'
            scan.result_file = str(output_file)
        else:
            scan.status = 'FAILED'
            scan.result_file = 'httpx did not produce output file'
    except subprocess.TimeoutExpired:
        scan.status = 'FAILED'
        scan.result_file = 'httpx timed out (300s)'
    except FileNotFoundError:
        scan.status = 'FAILED'
        scan.result_file = f'httpx not found at "{settings.HTTPX_PATH}"'
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_inql(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_url = f"https://{scan.target.domain}"
    output_file = settings.SCAN_OUTPUT_DIR / f'inql_{scan_id}.json'
    graphql_url = f"{target_url}/graphql"

    if isinstance(settings.INQL_PATH, list):
        command = settings.INQL_PATH + ['-t', graphql_url, '-o', str(output_file)]
    else:
        command = [settings.INQL_PATH, '-t', graphql_url, '-o', str(output_file)]

    try:
        subprocess.run(command, capture_output=True, text=True, timeout=300)

        introspection_query = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'
        resp = requests.post(graphql_url, json={'query': introspection_query}, timeout=10)
        if resp.status_code == 200:
            Endpoint.objects.get_or_create(
                target=scan.target,
                url=graphql_url,
                defaults={'technology': 'GraphQL', 'status_code': 200}
            )

        scan.status = 'COMPLETED'
        scan.result_file = str(output_file)
    except subprocess.TimeoutExpired:
        scan.status = 'FAILED'
        scan.result_file = 'InQL timed out (300s)'
    except FileNotFoundError:
        scan.status = 'FAILED'
        scan.result_file = f'InQL not found at "{settings.INQL_PATH}"'
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_gau(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_domain = scan.target.domain
    output_file = settings.SCAN_OUTPUT_DIR / f'gau_{scan_id}.txt'

    command = [
        settings.GAU_PATH,
        target_domain,
        '-o', str(output_file)
    ]

    try:
        subprocess.run(command, capture_output=True, text=True, timeout=300)

        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and url.startswith('http'):
                        Endpoint.objects.get_or_create(
                            target=scan.target,
                            url=url,
                            defaults={'technology': 'GAU'}
                        )

            scan.status = 'COMPLETED'
            scan.result_file = str(output_file)
        else:
            scan.status = 'FAILED'
            scan.result_file = 'GAU did not produce output file'
    except subprocess.TimeoutExpired:
        scan.status = 'FAILED'
        scan.result_file = 'GAU timed out (300s)'
    except FileNotFoundError:
        scan.status = 'FAILED'
        scan.result_file = f'GAU not found at "{settings.GAU_PATH}"'
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_waybackurls(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_domain = scan.target.domain
    output_file = settings.SCAN_OUTPUT_DIR / f'wayback_{scan_id}.txt'

    command = [
        settings.WAYBACKURLS_PATH,
        target_domain
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if result.stdout:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            for line in result.stdout.splitlines():
                url = line.strip()
                if url and url.startswith('http'):
                    Endpoint.objects.get_or_create(
                        target=scan.target,
                        url=url,
                        defaults={'technology': 'Waybackurls'}
                    )

            scan.status = 'COMPLETED'
            scan.result_file = str(output_file)
        else:
            scan.status = 'FAILED'
            scan.result_file = 'Waybackurls did not produce output'
    except subprocess.TimeoutExpired:
        scan.status = 'FAILED'
        scan.result_file = 'Waybackurls timed out (300s)'
    except FileNotFoundError:
        scan.status = 'FAILED'
        scan.result_file = f'Waybackurls not found at "{settings.WAYBACKURLS_PATH}"'
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_swagger(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_url = f"https://{scan.target.domain}"
    swagger_paths = ['/swagger.json', '/openapi.json', '/api-docs', '/swagger-ui', '/v2/api-docs']
    found_paths = []

    try:
        for path in swagger_paths:
            resp = requests.get(f"{target_url}{path}", timeout=10)
            if resp.status_code == 200:
                found_paths.append(path)
                try:
                    spec = resp.json()
                    for endpoint_path in spec.get('paths', {}):
                        Endpoint.objects.get_or_create(
                            target=scan.target,
                            url=f"{target_url}{endpoint_path}",
                            defaults={'technology': 'Swagger/OpenAPI', 'status_code': 200}
                        )
                except:
                    pass

        scan.status = 'COMPLETED'
        scan.result_file = json.dumps(found_paths)
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_soap_wsdl(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_url = f"https://{scan.target.domain}"
    wsdl_url = f"{target_url}/service?wsdl"
    output_file = settings.SCAN_OUTPUT_DIR / f'soap_{scan_id}.wsdl'

    try:
        resp = requests.get(wsdl_url, timeout=10)
        if resp.status_code == 200:
            with open(output_file, 'w') as f:
                f.write(resp.text)

            import re
            operations = re.findall(r'operation name="([^"]+)"', resp.text)
            for op in operations:
                Endpoint.objects.get_or_create(
                    target=scan.target,
                    url=f"{wsdl_url}#{op}",
                    defaults={'technology': 'SOAP', 'status_code': 200}
                )

            scan.status = 'COMPLETED'
            scan.result_file = str(output_file)
        else:
            scan.status = 'FAILED'
            scan.result_file = f'WSDL not found at {wsdl_url} (HTTP {resp.status_code})'
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_grpcurl(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_domain = scan.target.domain
    output_file = settings.SCAN_OUTPUT_DIR / f'grpcurl_{scan_id}.json'

    command = [
        settings.GRPCURL_PATH,
        '-plaintext',
        f'{target_domain}:443',
        'list'
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if result.stdout:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            for line in result.stdout.splitlines():
                service = line.strip()
                if service:
                    Endpoint.objects.get_or_create(
                        target=scan.target,
                        url=f'grpc://{target_domain}:443/{service}',
                        defaults={'technology': 'gRPC', 'status_code': 200}
                    )

            scan.status = 'COMPLETED'
            scan.result_file = str(output_file)
        else:
            scan.status = 'FAILED'
            scan.result_file = 'gRPCurl did not produce output'
    except subprocess.TimeoutExpired:
        scan.status = 'FAILED'
        scan.result_file = 'gRPCurl timed out (300s)'
    except FileNotFoundError:
        scan.status = 'FAILED'
        scan.result_file = f'gRPCurl not found at "{settings.GRPCURL_PATH}"'
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_full_workflow(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target = scan.target
    results = {'tech': [], 'endpoints': [], 'vulns': [], 'params': []}

    try:
        # Phase 1: Detect technology
        from Wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(f"https://{target.domain}", timeout=15)
        tech_results = wappalyzer.analyze_with_versions(webpage)
        for tech_name, info in tech_results.items():
            versions = info.get('versions', [])
            version = versions[0] if versions else None
            categories = info.get('categories', [])
            Technology.objects.update_or_create(
                target=target,
                name=tech_name,
                defaults={
                    'version': version,
                    'category': ', '.join(categories),
                    'detected_by': 'Wappalyzer'
                }
            )
            results['tech'].append(tech_name)

        # Phase 2: Dirsearch (always runs)
        dirsearch_scan = Scan.objects.create(target=target, scan_type='DIRSEARCH', status='PENDING')
        run_dirsearch(dirsearch_scan.id)

        # Phase 3: Tech-specific tools
        techs_lower = [t.lower() for t in results['tech']]
        if any(g in t for t in techs_lower for g in ['graphql', 'graphiql']):
            inql_scan = Scan.objects.create(target=target, scan_type='INQL', status='PENDING')
            run_inql(inql_scan.id)
        if any(s in t for t in techs_lower for s in ['swagger', 'openapi']):
            swagger_scan = Scan.objects.create(target=target, scan_type='SWAGGER', status='PENDING')
            run_swagger(swagger_scan.id)
        if any(s in t for t in techs_lower for s in ['soap', 'wsdl']):
            soap_scan = Scan.objects.create(target=target, scan_type='SOAP_WSDL', status='PENDING')
            run_soap_wsdl(soap_scan.id)
        if any(g in t for t in techs_lower for g in ['grpc']):
            grpc_scan = Scan.objects.create(target=target, scan_type='GRPCURL', status='PENDING')
            run_grpcurl(grpc_scan.id)

        # Phase 4: Arjun on all discovered endpoints
        from fuzzing.models import FuzzingQueue
        from fuzzing.tasks import run_arjun
        endpoints = Endpoint.objects.filter(target=target)
        for ep in endpoints:
            arjun_queue = FuzzingQueue.objects.create(endpoint=ep)
            run_arjun(arjun_queue.id)

        scan.status = 'COMPLETED'
        scan.result_file = json.dumps(results)
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()


@shared_task(bind=True)
def run_detection_scan(self, target_id, scan_types=None):
    from targets.models import Target
    from celery import current_app
    if scan_types is None:
        scan_types = ['HTTPX_TECH', 'DIRSEARCH', 'NUCLEI', 'SSL_CHECK']

    try:
        target = Target.objects.get(id=target_id)
    except Target.DoesNotExist:
        return {'error': 'Target not found'}

    results = {'target': target.domain, 'scans': {}}
    for st in scan_types:
        task_name = SCAN_TASK_MAP.get(st)
        if task_name:
            scan = Scan.objects.create(target=target, scan_type=st, status='PENDING')
            current_app.send_task(task_name, args=[scan.id])
            results['scans'][st] = {'scan_id': scan.id, 'status': 'queued'}

    return results


@shared_task(bind=True)
def run_periodic_monitor(self, schedule_id):
    from .models import MonitorSchedule, DetectionResult
    from celery import current_app
    from django.utils import timezone

    try:
        schedule = MonitorSchedule.objects.get(id=schedule_id)
    except MonitorSchedule.DoesNotExist:
        return {'error': 'Schedule not found'}

    if not schedule.is_active:
        return {'status': 'inactive'}

    target = schedule.target
    scan_types = [s.strip() for s in schedule.scan_types.split(',')]

    schedule.last_run = timezone.now()
    schedule.save()

    results = {'target': target.domain, 'scans': []}
    for st in scan_types:
        task_name = SCAN_TASK_MAP.get(st)
        if task_name:
            scan = Scan.objects.create(target=target, scan_type=st, status='PENDING')
            current_app.send_task(task_name, args=[scan.id])
            results['scans'].append({'type': st, 'scan_id': scan.id})

    return results


@shared_task(bind=True)
def monitor_ssl_expiry(self):
    from .models import SSLResult, DetectionResult
    from django.utils import timezone
    from datetime import timedelta

    threshold = timezone.now() + timedelta(days=30)
    expired_ssl = SSLResult.objects.filter(scanned_at__lt=threshold)

    for ssl in expired_ssl:
        DetectionResult.objects.create(
            target=ssl.target,
            detection_type='SSL_EXPIRY_CHECK',
            status='CHANGED',
            details=f'SSL certificate for {ssl.host} may be expiring soon',
            current_value=ssl.grade or 'Unknown',
        )

    return {'checked': expired_ssl.count(), 'alerts': expired_ssl.count()}


@shared_task(bind=True)
def monitor_new_vulnerabilities(self):
    from vulnerabilities.models import Vulnerability
    from .models import DetectionResult
    from django.utils import timezone
    from datetime import timedelta

    since = timezone.now() - timedelta(days=1)
    new_vulns = Vulnerability.objects.filter(discovered_on__gte=since)

    for vuln in new_vulns:
        DetectionResult.objects.create(
            target=vuln.target,
            detection_type='NEW_VULNERABILITY',
            status='NEW',
            details=f'{vuln.title} ({vuln.severity})',
            current_value=vuln.cve_id or vuln.title,
        )

    return {'new_vulns': new_vulns.count()}


@shared_task(bind=True)
def monitor_endpoint_changes(self):
    from targets.models import Endpoint
    from .models import DetectionResult
    from django.utils import timezone
    from datetime import timedelta

    since = timezone.now() - timedelta(days=1)
    new_endpoints = Endpoint.objects.filter(discovered_on__gte=since)

    for ep in new_endpoints:
        DetectionResult.objects.create(
            target=ep.target,
            detection_type='NEW_ENDPOINT',
            status='NEW',
            details=f'New endpoint discovered: {ep.url}',
            current_value=ep.url,
        )

    return {'new_endpoints': new_endpoints.count()}


@shared_task(bind=True)
def run_wapiti(self, scan_id):
    """
    Executes Python web vulnerability scanner (replacing Wapiti)
    and persists discovered vulnerabilities to DB.
    """
    scan = Scan.objects.get(id=scan_id)
    scan.status = 'RUNNING'
    scan.celery_task_id = self.request.id
    scan.save()

    target_domain = scan.target.domain
    target_url = f"https://{target_domain}"
    output_file = settings.SCAN_OUTPUT_DIR / f'wapiti_{scan_id}.json'

    try:
        from attacksurface.scanner.vulnerability_scanner import run_python_vuln_scanner
        httpx_items = [{"url": target_url, "headers": {}, "status_code": 0}]
        findings = run_python_vuln_scanner(target_domain, httpx_items)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json.dumps(findings, indent=2))

        for item in findings:
            title = item.get('finding') or item.get('vulnerability_id') or 'Vulnerability Discovered'
            severity = str(item.get('severity') or 'MEDIUM').upper()

            Vulnerability.objects.get_or_create(
                target=scan.target,
                title=title[:255],
                defaults={
                    'severity': severity,
                    'description': item.get('finding', ''),
                    'remediation': 'Apply recommended security headers and configuration updates.',
                    'source_tool': 'PythonScanner',
                    'references': target_url,
                }
            )

        scan.status = 'COMPLETED'
        scan.result_file = str(output_file)
    except Exception as e:
        scan.status = 'FAILED'
        scan.result_file = str(e)
    finally:
        scan.completed_at = timezone.now()
        scan.save()

