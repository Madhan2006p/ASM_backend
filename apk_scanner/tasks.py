import os
import json
import hashlib
import zipfile
import xml.etree.ElementTree as ET
from celery import shared_task
from django.utils import timezone
from django.conf import settings


DANGEROUS_PERMISSIONS = [
    'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
    'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
    'READ_CALL_LOG', 'WRITE_CALL_LOG', 'CALL_PHONE', 'READ_EXTERNAL_STORAGE',
    'WRITE_EXTERNAL_STORAGE', 'INTERNET', 'ACCESS_NETWORK_STATE', 'ACCESS_WIFI_STATE',
    'BLUETOOTH', 'BLUETOOTH_ADMIN', 'BODY_SENSORS', 'READ_CALENDAR', 'WRITE_CALENDAR',
    'ACCESS_BACKGROUND_LOCATION', 'ACTIVITY_RECOGNITION',
]


def extract_manifest_basic(apk_path):
    info = {
        'package_name': None, 'version_name': None, 'version_code': None,
        'min_sdk': None, 'target_sdk': None, 'app_name': None,
        'permissions': [], 'activities': [], 'services': [],
        'receivers': [], 'providers': [],
    }
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            if 'AndroidManifest.xml' not in z.namelist():
                raise ValueError('AndroidManifest.xml not found in APK')
            raw = z.read('AndroidManifest.xml')
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                raise ValueError('Invalid AndroidManifest.xml')

            ns = '{http://schemas.android.com/apk/res/android}'
            manifest = root
            info['package_name'] = manifest.get('package')
            info['version_name'] = manifest.get(f'{ns}versionName')
            info['version_code'] = manifest.get(f'{ns}versionCode')

            for child in root.iter():
                tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                if tag == 'uses-permission':
                    perm = child.get(f'{ns}name', '')
                    if perm:
                        info['permissions'].append(perm)
                elif tag == 'activity':
                    name = child.get(f'{ns}name', '')
                    if name:
                        info['activities'].append(name)
                elif tag == 'service':
                    name = child.get(f'{ns}name', '')
                    if name:
                        info['services'].append(name)
                elif tag == 'receiver':
                    name = child.get(f'{ns}name', '')
                    if name:
                        info['receivers'].append(name)
                elif tag == 'provider':
                    name = child.get(f'{ns}name', '')
                    if name:
                        info['providers'].append(name)
                elif tag == 'uses-sdk':
                    info['min_sdk'] = child.get(f'{ns}minSdkVersion')
                    info['target_sdk'] = child.get(f'{ns}targetSdkVersion')

            app_elem = root.find('application')
            if app_elem is not None:
                info['app_name'] = app_elem.get(f'{ns}label', '')
    except zipfile.BadZipFile:
        raise ValueError('File is not a valid ZIP/APK archive')
    return info


def analyze_permissions(perms):
    dangerous = []
    for p in perms:
        short = p.split('.')[-1].upper()
        if short in DANGEROUS_PERMISSIONS:
            dangerous.append(p)

    severity = 'INFO'
    dangerous_count = len(dangerous)

    if dangerous_count >= 8:
        severity = 'HIGH'
    elif dangerous_count >= 4:
        severity = 'MEDIUM'
    elif dangerous_count >= 1:
        severity = 'LOW'

    return dangerous, severity


@shared_task(bind=True)
def analyze_apk_file(self, apk_id):
    from .models import APKFile, APKAnalysis

    try:
        apk_file = APKFile.objects.get(id=apk_id)
    except APKFile.DoesNotExist:
        return

    apk_file.status = 'ANALYZING'
    apk_file.celery_task_id = self.request.id
    apk_file.save()

    apk_path = apk_file.file.path

    try:
        md5_hash = hashlib.md5()
        with open(apk_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5_hash.update(chunk)
        apk_file.md5_hash = md5_hash.hexdigest()
        apk_file.save()

        manifest_info = extract_manifest_basic(apk_path)
        dangerous_perms, severity = analyze_permissions(manifest_info['permissions'])

        findings = []

        if dangerous_perms:
            findings.append(f"Contains {len(dangerous_perms)} dangerous permissions: {', '.join(dangerous_perms)}")

        if manifest_info.get('min_sdk') and int(manifest_info['min_sdk']) < 21:
            findings.append(f"Low minSdkVersion ({manifest_info['min_sdk']}) - app may run on outdated/insecure Android versions")

        if manifest_info.get('target_sdk') and int(manifest_info['target_sdk']) < 30:
            findings.append(f"Low targetSdkVersion ({manifest_info['target_sdk']}) - app may not use modern security features")

        try:
            from androguard.misc import AnalyzeAPK
            a, d, dx = AnalyzeAPK(apk_path)
            activities = list(set(a.get_activities()))
            services = list(set(a.get_services()))
            receivers = list(set(a.get_receivers()))
            providers = list(set(a.get_providers()))
            if activities:
                manifest_info['activities'] = activities
            if services:
                manifest_info['services'] = services
            if receivers:
                manifest_info['receivers'] = receivers
            if providers:
                manifest_info['providers'] = providers

            if manifest_info.get('activities'):
                for act in manifest_info['activities']:
                    if 'exported' in str(act).lower():
                        findings.append(f"Exported activity detected (potential attack surface): {act}")
        except ImportError:
            findings.append("Androguard not installed - using basic ZIP/XML parsing only")

        if not findings:
            findings.append("No major security issues detected via automated analysis")

        analysis = APKAnalysis.objects.create(
            apk=apk_file,
            package_name=manifest_info.get('package_name'),
            version_name=manifest_info.get('version_name'),
            version_code=manifest_info.get('version_code'),
            min_sdk=manifest_info.get('min_sdk'),
            target_sdk=manifest_info.get('target_sdk'),
            app_name=manifest_info.get('app_name'),
            permissions=json.dumps(manifest_info.get('permissions', []), indent=2),
            activities=json.dumps(manifest_info.get('activities', []), indent=2),
            services=json.dumps(manifest_info.get('services', []), indent=2),
            receivers=json.dumps(manifest_info.get('receivers', []), indent=2),
            providers=json.dumps(manifest_info.get('providers', []), indent=2),
            dangerous_permissions=json.dumps(dangerous_perms, indent=2),
            findings=json.dumps(findings, indent=2),
            severity=severity,
        )

        apk_file.status = 'COMPLETED'
        apk_file.save()

    except Exception as e:
        apk_file.status = 'FAILED'
        apk_file.save()
        raise e
