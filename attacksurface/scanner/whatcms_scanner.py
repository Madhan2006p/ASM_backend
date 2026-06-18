import requests
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

def run_whatcms(targets):
    """
    Fast technology and version scanning using WhatCMS API.
    Requires WHATCMS_API_KEY environment variable.
    """
    api_key = os.environ.get("WHATCMS_API_KEY")
    if not api_key:
        logger.warning("WHATCMS_API_KEY not found in environment. Skipping WhatCMS fast version scanning.")
        return []

    results = []
    
    def fetch_whatcms(target):
        try:
            resp = requests.get(
                "https://whatcms.org/API/Tech",
                params={"key": api_key, "url": target},
                timeout=3
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("result", {}).get("code") == 200:
                    techs = []
                    for item in data.get("results", []):
                        name = item.get("name")
                        version = item.get("version")
                        if version:
                            techs.append(f"{name}/{version} [WhatCMS]")
                        else:
                            techs.append(f"{name} [WhatCMS]")
                    
                    if techs:
                        return {
                            "url": target,
                            "domain": target,
                            "technologies": techs
                        }
        except Exception as e:
            logger.debug(f"WhatCMS API failed for {target}: {e}")
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(fetch_whatcms, target): target for target in targets}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
                
    return results
