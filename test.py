import requests
response = requests.get(
    'https://cvefeed.io/api/user/products/cve-feed',
    headers={'Authorization': 'Token 3657650656526e135b439aa5e3800de5f0c0fa5d'}
)                        
# Example response
print(response.json())