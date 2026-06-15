import subprocess
import json
from celery import shared_task
from django.utils import timezone
from .models import FuzzingQueue, FuzzingResult
from django.conf import settings

@shared_task(bind=True)
def run_arjun(self, queue_id):
    queue = FuzzingQueue.objects.get(id=queue_id)
    queue.status = 'RUNNING'
    queue.celery_task_id = self.request.id
    queue.save()

    endpoint = queue.endpoint
    output_file = settings.SCAN_OUTPUT_DIR / f'arjun_{queue_id}.json'

    command = [
        settings.ARJUN_PATH,
        '-u', endpoint.url,
        '-oT', str(output_file),
    ]

    method = getattr(endpoint, 'method', 'GET')
    if method == 'POST':
        command.extend(['-m', 'POST'])
    elif method == 'JSON':
        command.extend(['-m', 'JSON'])
    else:
        command.extend(['-m', 'GET'])

    auth_header = getattr(endpoint, 'auth_header', None)
    if auth_header:
        command.extend(['-H', auth_header])

    auth_cookie = getattr(endpoint, 'auth_cookie', None)
    if auth_cookie:
        command.extend(['-c', auth_cookie])

    try:
        subprocess.run(command, capture_output=True, text=True, timeout=300)

        if output_file.exists():
            with open(output_file, 'r') as f:
                data = json.load(f)
                params = data.get(endpoint.url, {}).get('params', [])
                if not params:
                    for url_key in data:
                        entry = data[url_key]
                        if isinstance(entry, dict) and 'params' in entry:
                            params = entry['params']
                            break
                for param in params:
                    FuzzingResult.objects.get_or_create(
                        endpoint=endpoint,
                        parameter=param if isinstance(param, str) else param.get('name', str(param)),
                        defaults={'method': method}
                    )

        queue.status = 'COMPLETED'
    except Exception as e:
        queue.status = 'FAILED'
    finally:
        queue.completed_at = timezone.now()
        queue.save()
