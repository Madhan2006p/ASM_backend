import os
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.contrib.auth.models import User
from targets.models import Target, Endpoint
from scans.models import Scan
from fuzzing.models import FuzzingQueue, FuzzingResult
from vulnerabilities.models import Vulnerability
from django.utils import timezone

def seed():
    print("Starting data seeding...")

    # 1. Get or create superuser
    user = User.objects.filter(is_superuser=True).first()
    if not user:
        username = os.getenv('ADMIN_USERNAME', 'admin')
        email = os.getenv('ADMIN_EMAIL', 'admin@localhost')
        password = os.getenv('ADMIN_PASSWORD', 'changeme')
        user = User.objects.create_superuser(username, email, password)
        print("Superuser created.")
    else:
        print(f"Using existing superuser: {user.username}")

    # 2. Create Target
    target, created = Target.objects.get_or_create(
        domain='example.com',
        user=user,
        defaults={'description': 'Example target for API Recon & Discovery testing'}
    )
    if created:
        print(f"Created target: {target.domain}")
    else:
        print(f"Target already exists: {target.domain}")

    # 3. Create Scans
    scans_data = [
        ('DIRSEARCH', 'COMPLETED'),
        ('HTTPX', 'COMPLETED'),
        ('NUCLEI', 'COMPLETED'),
        ('NMAP', 'COMPLETED'),
    ]
    for scan_type, status in scans_data:
        scan, created = Scan.objects.get_or_create(
            target=target,
            scan_type=scan_type,
            defaults={
                'status': status,
                'started_at': timezone.now(),
                'completed_at': timezone.now(),
                'result_file': f'/mock_outputs/{scan_type.lower()}_result.json'
            }
        )
        if created:
            print(f"Created scan entry: {scan_type}")

    # 4. Create Endpoints (Dirsearch and HTTPX results)
    endpoints_data = [
        ('/api/v1/users', 'GET', 200, 'REST'),
        ('/api/v1/auth/login', 'POST', 200, 'REST'),
        ('/graphql', 'POST', 200, 'GraphQL'),
        ('/swagger.json', 'GET', 200, 'Swagger/OpenAPI'),
        ('/api-docs', 'GET', 403, 'Swagger/OpenAPI'),
        ('/service?wsdl', 'GET', 200, 'SOAP'),
    ]
    
    endpoints = []
    for path, method, status_code, tech in endpoints_data:
        url = f"https://{target.domain}{path}"
        ep, created = Endpoint.objects.get_or_create(
            target=target,
            url=url,
            method=method,
            defaults={
                'status_code': status_code,
                'technology': tech
            }
        )
        endpoints.append(ep)
        if created:
            print(f"Created Endpoint: {method} {url}")

    # 5. Create Fuzzing Queue & Fuzzing Results (Arjun results)
    for ep in endpoints:
        # Create a mock queue
        fq, created = FuzzingQueue.objects.get_or_create(
            endpoint=ep,
            defaults={
                'status': 'COMPLETED',
                'started_at': timezone.now(),
                'completed_at': timezone.now(),
            }
        )
        
        # Add mock discovered parameters
        if 'users' in ep.url:
            params = ['id', 'limit', 'offset', 'role']
        elif 'login' in ep.url:
            params = ['username', 'password', 'remember_me']
        elif 'graphql' in ep.url:
            params = ['query', 'variables', 'operationName']
        elif 'wsdl' in ep.url:
            params = ['wsdl', 'op']
        else:
            params = ['format']
            
        for param in params:
            res, created = FuzzingResult.objects.get_or_create(
                endpoint=ep,
                parameter=param,
                method=ep.method,
                defaults={'is_vulnerable': param in ['id', 'query']}
            )
            if created:
                print(f"Discovered parameter: {param} on {ep.url}")

    # 6. Create Vulnerabilities (Nuclei / Scan findings)
    vulns_data = [
        ('GraphQL Introspection Enabled', 'MEDIUM', 'Introspection query is enabled on the GraphQL endpoint, revealing the entire database schema.', 'Disable introspection in production configuration.', 'Nuclei'),
        ('Exposed Swagger API Documentation', 'LOW', 'Publicly accessible Swagger UI page is exposed at /swagger.json.', 'Restrict access to authorized IP ranges only.', 'Nuclei'),
        ('Missing HTTP Security Headers', 'INFO', 'The target web server is missing security hardening headers (X-Frame-Options, CSP, HSTS).', 'Configure strict web security headers on the reverse proxy.', 'HTTPX'),
    ]
    
    for title, severity, desc, rem, tool in vulns_data:
        vuln, created = Vulnerability.objects.get_or_create(
            target=target,
            title=title,
            defaults={
                'severity': severity,
                'description': desc,
                'remediation': rem,
                'source_tool': tool,
                'is_resolved': False
            }
        )
        if created:
            print(f"Registered vulnerability: {title}")

    print("Seeding completed successfully!")

if __name__ == '__main__':
    seed()
