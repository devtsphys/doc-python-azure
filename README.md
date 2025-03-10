# doc-python-azure

- [Azure Identity](#azure-identity)
- [Azure Key Vault](#azure-keyvault)
- [Azure File Storage](#azure-filestorage)
- [Azure Blob Storage](#azure-blob-storage)
- [Azure Machine Learning](#azure-machine-learning)
- [Azure Kubernetes](#azure-kubernetes)

## Azure Identity

# Python Azure Identity Reference Card

## Basic Concepts

### Azure Identity Overview
The Azure Identity library for Python provides token authentication support for the Azure SDK. It simplifies authentication across various Azure services by abstracting credential types and providing a consistent authentication experience.

### Key Components
- **Credentials**: Objects that authenticate with Azure Active Directory (AAD)
- **TokenCredential**: Base abstract class implemented by all credential types
- **Token**: Represents an AAD access token with value and expiration time

## Credential Types

### Interactive Credentials
| Credential | Use Case | Features |
|------------|----------|----------|
| `InteractiveBrowserCredential` | Desktop applications | Opens browser for user to sign in |
| `DeviceCodeCredential` | Devices without browsers | Provides code to enter on another device |
| `UsernamePasswordCredential` | Legacy applications | Simple username/password login |

### Non-interactive Credentials
| Credential | Use Case | Features |
|------------|----------|----------|
| `ClientSecretCredential` | Service principals | Uses client ID, tenant ID, and client secret |
| `CertificateCredential` | Service principals | Uses client ID, tenant ID, and certificate |
| `ManagedIdentityCredential` | Azure services | Uses managed identity assigned to Azure resource |

### Composite Credentials
| Credential | Use Case | Features |
|------------|----------|----------|
| `ChainedTokenCredential` | Multiple auth methods | Tries multiple credentials in sequence |
| `DefaultAzureCredential` | General purpose | Tries common credentials in a predefined order |

## Installation

```bash
pip install azure-identity
```

## Basic Usage Examples

### DefaultAzureCredential
```python
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

# Create credential
credential = DefaultAzureCredential()

# Use credential with Azure service
blob_service = BlobServiceClient(
    account_url="https://myaccount.blob.core.windows.net",
    credential=credential
)
```

### ClientSecretCredential
```python
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient

# Create credential
credential = ClientSecretCredential(
    tenant_id="tenant-id-value",
    client_id="client-id-value",
    client_secret="client-secret-value"
)

# Use credential with Key Vault
secret_client = SecretClient(
    vault_url="https://myvault.vault.azure.net/",
    credential=credential
)
```

### ManagedIdentityCredential
```python
from azure.identity import ManagedIdentityCredential
from azure.mgmt.resource import ResourceManagementClient

# Create credential (optionally specify client_id for user-assigned identity)
credential = ManagedIdentityCredential(client_id="client-id-value")  # client_id is optional

# Use credential with Azure management API
resource_client = ResourceManagementClient(
    credential=credential,
    subscription_id="subscription-id-value"
)
```

## Advanced Techniques

### Chained Credentials
```python
from azure.identity import (
    ClientSecretCredential,
    ManagedIdentityCredential,
    ChainedTokenCredential
)

# Create individual credentials
client_credential = ClientSecretCredential(
    tenant_id="tenant-id-value",
    client_id="client-id-value",
    client_secret="client-secret-value"
)
managed_credential = ManagedIdentityCredential()

# Chain credentials (first successful credential will be used)
credential = ChainedTokenCredential(managed_credential, client_credential)
```

### DefaultAzureCredential Configuration
```python
from azure.identity import DefaultAzureCredential

# Configure DefaultAzureCredential with options
credential = DefaultAzureCredential(
    exclude_shared_token_cache_credential=True,
    exclude_visual_studio_code_credential=True,
    managed_identity_client_id="client-id-value",
    interactive_browser_tenant_id="tenant-id-value"
)
```

### Credential with Proxy
```python
from azure.identity import ClientSecretCredential
import os

# Configure proxy settings
os.environ["HTTP_PROXY"] = "http://proxy:8080"
os.environ["HTTPS_PROXY"] = "https://proxy:8080"

# Create credential (will use proxy settings)
credential = ClientSecretCredential(
    tenant_id="tenant-id-value",
    client_id="client-id-value",
    client_secret="client-secret-value"
)
```

### Custom Transport
```python
from azure.identity import DefaultAzureCredential
from azure.core.pipeline.transport import RequestsTransport

# Create custom transport with specific configurations
transport = RequestsTransport(connection_timeout=30, read_timeout=90)

# Create credential with custom transport
credential = DefaultAzureCredential(transport=transport)
```

## Token Cache and Persistence

### SharedTokenCacheCredential
```python
from azure.identity import SharedTokenCacheCredential

# Use tokens from shared token cache
credential = SharedTokenCacheCredential(
    username="user@example.com",
    tenant_id="tenant-id-value"  # Optional
)
```

### Token Cache with Persistence
```python
from azure.identity import InteractiveBrowserCredential
from azure.identity.aio import InteractiveBrowserCredential as AsyncInteractiveBrowserCredential
from azure.identity._persistence import TokenCachePersistenceOptions

# Configure persistence options
cache_options = TokenCachePersistenceOptions(
    name="my-app-cache",
    allow_unencrypted_storage=False
)

# Use with synchronous credential
credential = InteractiveBrowserCredential(
    cache_persistence_options=cache_options
)

# Use with asynchronous credential
async_credential = AsyncInteractiveBrowserCredential(
    cache_persistence_options=cache_options
)
```

## Asynchronous Credentials

### Async Credential Usage
```python
from azure.identity.aio import DefaultAzureCredential
from azure.keyvault.secrets.aio import SecretClient
import asyncio

async def get_secret():
    # Create async credential
    credential = DefaultAzureCredential()
    
    # Use with async client
    client = SecretClient(
        vault_url="https://myvault.vault.azure.net/",
        credential=credential
    )
    
    # Get secret asynchronously
    secret = await client.get_secret("my-secret")
    return secret.value

# Run async function
secret_value = asyncio.run(get_secret())
```

## Environment Variables

### Common Environment Variables
| Variable | Used By | Purpose |
|----------|---------|---------|
| `AZURE_TENANT_ID` | DefaultAzureCredential | Tenant ID for authentication |
| `AZURE_CLIENT_ID` | DefaultAzureCredential | Client/App ID for authentication |
| `AZURE_CLIENT_SECRET` | DefaultAzureCredential | Client secret for service principal |
| `AZURE_USERNAME` | DefaultAzureCredential | Username for interactive auth |
| `AZURE_PASSWORD` | DefaultAzureCredential | Password for username/password auth |
| `AZURE_AUTHORITY_HOST` | All credentials | Custom AAD authority host |

## Troubleshooting

### Enable Logging
```python
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Focus on Azure Identity logs
azure_logger = logging.getLogger('azure.identity')
azure_logger.setLevel(logging.DEBUG)
azure_logger.addHandler(logging.StreamHandler(stream=sys.stdout))
```

### Common Errors and Solutions

| Error | Possible Cause | Solution |
|-------|----------------|----------|
| `CredentialUnavailableError` | No applicable credential | Check environment variables or provide explicit credential |
| `ClientAuthenticationError` | Invalid credentials | Verify credential values and permissions |
| `AuthenticationRequiredError` | Token expired or invalid | Reauthenticate with fresh credentials |
| `TokenExpiredError` | Access token expired | System will automatically refresh if possible |

## Best Practices

### Security Best Practices
1. **Use managed identities** when possible for Azure resources
2. **Avoid hardcoded secrets** in code - use environment variables or Azure Key Vault
3. **Implement least privilege** - request only necessary scopes and permissions
4. **Rotate secrets regularly** to minimize impact of potential leaks
5. **Use certificates** instead of secrets for service principals when possible

### Performance Best Practices
1. **Reuse credentials** across application lifetime
2. **Leverage token caching** to reduce authentication calls
3. **Use `DefaultAzureCredential`** for general applications to simplify configuration
4. **Configure appropriate timeouts** for authentication requests
5. **Use async credentials** with async clients for non-blocking operations

### Development Best Practices
1. **Use different credentials** for development, testing, and production
2. **Configure CI/CD pipelines** with service principals dedicated to automation
3. **Monitor authentication failures** to detect potential issues
4. **Document credential requirements** for your application
5. **Keep the Azure Identity library updated** for security fixes and new features

## Example Scenarios

### Web Application on Azure App Service
```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# In production: uses managed identity
# In development: uses developer credentials
credential = DefaultAzureCredential()

# Access secrets from Key Vault
secret_client = SecretClient(
    vault_url="https://myvault.vault.azure.net/",
    credential=credential
)
db_connection = secret_client.get_secret("db-connection-string").value
```

### Background Process with Service Principal
```python
from azure.identity import ClientSecretCredential
from azure.storage.blob import BlobServiceClient
import os

# Get values from environment variables
tenant_id = os.environ["AZURE_TENANT_ID"]
client_id = os.environ["AZURE_CLIENT_ID"]
client_secret = os.environ["AZURE_CLIENT_SECRET"]

# Create service principal credential
credential = ClientSecretCredential(
    tenant_id=tenant_id,
    client_id=client_id,
    client_secret=client_secret
)

# Use credential for storage operations
blob_service = BlobServiceClient(
    account_url="https://myaccount.blob.core.windows.net",
    credential=credential
)
```


## Azure KeyVault

# Azure Key Vault Secrets Python Package Cheat Sheet

## Basic Information

- **Package Name**: `azure-keyvault-secrets`
- **Latest Version**: 4.7.0 (as of October 2024)
- **Purpose**: Interact with Azure Key Vault's secrets management service from Python applications
- **GitHub**: [azure-sdk-for-python/sdk/keyvault/azure-keyvault-secrets](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/keyvault/azure-keyvault-secrets)
- **PyPI**: [azure-keyvault-secrets](https://pypi.org/project/azure-keyvault-secrets/)

## Installation

```bash
pip install azure-keyvault-secrets
```

For authentication, also install:
```bash
pip install azure-identity
```

## Core Components

### Client Classes

- `SecretClient`: Main client for interacting with Azure Key Vault Secrets service
- `SecretProperties`: Properties of a Key Vault secret
- `KeyVaultSecret`: Represents a complete secret with its value and properties
- `DeletedSecret`: Represents a deleted secret

### Authentication Classes (from azure-identity)

- `DefaultAzureCredential`: Recommended for most scenarios, tries multiple authentication methods
- `ClientSecretCredential`: For service principal authentication
- `ManagedIdentityCredential`: For VM/app service managed identities
- `InteractiveBrowserCredential`: For interactive login scenarios
- `EnvironmentCredential`: Uses environment variables

## Basic Usage

### Client Initialization

```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Key Vault URL format: https://<vault-name>.vault.azure.net/
vault_url = "https://your-key-vault-name.vault.azure.net/"
credential = DefaultAzureCredential()
client = SecretClient(vault_url=vault_url, credential=credential)
```

### Secret Operations

#### Set a Secret

```python
secret = client.set_secret("secret-name", "secret-value")
print(f"Secret created with name '{secret.name}'")
```

#### Get a Secret

```python
secret = client.get_secret("secret-name")
print(f"Secret value: {secret.value}")
```

#### List Secrets

```python
# List secrets
secrets = client.list_properties_of_secrets()
for secret in secrets:
    print(f"Secret: {secret.name}, Enabled: {secret.enabled}")
```

#### Delete a Secret

```python
# Soft delete (recoverable)
delete_operation = client.begin_delete_secret("secret-name")
deleted_secret = delete_operation.result()
print(f"Secret '{deleted_secret.name}' has been deleted")

# Permanently delete (after soft delete, if vault has purge protection disabled)
client.purge_deleted_secret("secret-name")
```

#### Recover a Deleted Secret

```python
recover_operation = client.begin_recover_deleted_secret("secret-name")
recovered_secret = recover_operation.result()
print(f"Secret '{recovered_secret.name}' has been recovered")
```

## Advanced Features

### Secret Versioning

```python
# Set a new version of a secret
updated_secret = client.set_secret("secret-name", "new-secret-value")

# Get a specific version of a secret
versions = client.list_properties_of_secret_versions("secret-name")
for version in versions:
    specific_version = client.get_secret("secret-name", version=version.version)
    print(f"Version {version.version}: {specific_version.value}")
```

### Secret Metadata and Properties

```python
# Set a secret with metadata and properties
from datetime import datetime, timedelta, timezone

# Set expiration and activation time
expires_on = datetime.now(timezone.utc) + timedelta(days=30)
not_before = datetime.now(timezone.utc) + timedelta(days=1)

secret = client.set_secret(
    "secret-name", 
    "secret-value",
    content_type="text/plain",  # Content type
    enabled=True,              # Is the secret enabled for use?
    expires_on=expires_on,     # When the secret will expire
    not_before=not_before,     # When the secret becomes valid
    tags={"env": "production", "app": "myapp"}  # Custom metadata
)

# Update secret properties
updated_properties = client.update_secret_properties(
    "secret-name",
    enabled=False,
    tags={"env": "staging", "app": "myapp"}
)
```

### Backup and Restore

```python
# Backup a secret
backup = client.backup_secret("secret-name")

# Restore a secret from backup
restored_secret = client.restore_secret_backup(backup)
```

### Error Handling

```python
from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError

try:
    secret = client.get_secret("non-existent-secret")
except ResourceNotFoundError as e:
    print(f"Secret not found: {e}")

try:
    client.set_secret("duplicate-name", "value1")
    client.set_secret("duplicate-name", "value2")  # This will create a new version, not throw an error
except ResourceExistsError as e:
    print(f"Error: {e}")  # This won't typically happen with secrets
```

## Best Practices

### Authentication

- Use managed identities in production environments
- Use least privilege roles (Key Vault Secrets User for reading, Key Vault Secrets Officer for writing)
- Don't hardcode credentials in code
- Rotate credentials regularly

```python
# Managed Identity (preferred for Azure services)
from azure.identity import ManagedIdentityCredential
credential = ManagedIdentityCredential()

# Service Principal (for applications)
from azure.identity import ClientSecretCredential
credential = ClientSecretCredential(
    tenant_id="your-tenant-id",
    client_id="your-client-id",
    client_secret="your-client-secret"
)
```

### Secret Management

- Use descriptive naming conventions (e.g., `app-db-password-prod`)
- Set appropriate expiration dates for sensitive secrets
- Use tags for better organization and filtering
- Consider using secret rotation patterns
- Implement proper secret versioning strategy

### Performance Optimization

- Cache secrets locally when appropriate (with proper security measures)
- Use connection pooling
- Implement retry policies for transient failures

```python
# Example of caching a secret in memory with expiration
import time
from functools import lru_cache

@lru_cache(maxsize=100)
def get_cached_secret(name, max_age_seconds=300):
    """Get a secret with caching for improved performance"""
    if name not in _secret_cache or (time.time() - _secret_cache[name]['timestamp'] > max_age_seconds):
        _secret_cache[name] = {
            'value': client.get_secret(name).value,
            'timestamp': time.time()
        }
    return _secret_cache[name]['value']

# Initialize cache
_secret_cache = {}
```

### Security Considerations

- Log secret access but never log secret values
- Implement proper RBAC in Azure Key Vault
- Use separate key vaults for different environments
- Enable soft-delete and purge protection on vaults
- Consider using Azure Private Link for network isolation

### Monitoring and Auditing

```python
# Enable diagnostic logs in Azure Portal or using Azure CLI
# Then use Azure Monitor to track operations

# When retrieving secrets, you can add auditing in your code
def get_secret_with_audit(client, secret_name):
    """Get secret with audit logging"""
    try:
        secret = client.get_secret(secret_name)
        # Log access (but not the value!)
        logger.info(f"Secret '{secret_name}' accessed successfully by {current_user}")
        return secret.value
    except Exception as e:
        logger.error(f"Failed to access secret '{secret_name}': {str(e)}")
        raise
```

## Integration Patterns

### With Azure Functions

```python
# requirements.txt
# azure-identity
# azure-keyvault-secrets

# In function_app.py
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Initialize once at module level for better performance
credential = DefaultAzureCredential()
secret_client = SecretClient(
    vault_url="https://your-keyvault.vault.azure.net/", 
    credential=credential
)

def main(req: func.HttpRequest) -> func.HttpResponse:
    # Get secret only when needed
    db_connection = secret_client.get_secret("db-connection-string").value
    # Use the secret...
```

### With Environment Variables (Hybrid Approach)

```python
import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

def get_config(key):
    """Get configuration from environment variables or Key Vault fallback"""
    # First try environment variables (for local dev or container settings)
    value = os.environ.get(key)
    if value:
        return value
        
    # Fall back to Key Vault (translate name format if needed)
    key_vault_name = key.lower().replace("_", "-")
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(
            vault_url=f"https://{os.environ['KEY_VAULT_NAME']}.vault.azure.net/",
            credential=credential
        )
        return client.get_secret(key_vault_name).value
    except Exception as e:
        print(f"Failed to retrieve {key} from Key Vault: {e}")
        return None
```

### With Config Libraries

```python
# Using python-decouple with Key Vault
from decouple import config
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

class KeyVaultConfig:
    def __init__(self, vault_url):
        self.client = SecretClient(
            vault_url=vault_url,
            credential=DefaultAzureCredential()
        )
        
    def __call__(self, key, default=None):
        # First try environment variables via decouple
        value = config(key, default=None)
        if value is not None:
            return value
            
        # Fall back to Key Vault
        try:
            return self.client.get_secret(key.lower().replace("_", "-")).value
        except:
            return default

# Usage
config = KeyVaultConfig("https://your-keyvault.vault.azure.net/")
database_url = config("DATABASE_URL")
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**:
   - Check if the identity has proper access to Key Vault
   - Verify that tenant ID, client ID, and client secret are correct
   - Ensure the Key Vault exists and is accessible from your network

2. **Access Denied**:
   - Check Key Vault access policies or RBAC permissions
   - Verify that the identity has appropriate permissions (Get, List, Set, etc.)

3. **Network Issues**:
   - Check if Key Vault is behind a firewall or private endpoint
   - Verify that your application can reach the Key Vault endpoint

4. **Secret Not Found**:
   - Check for typos in secret names
   - Verify that the secret exists in the specified vault
   - Check if the secret was soft-deleted

### Diagnostic Logging

```python
import logging
import sys
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('azure')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(stream=sys.stdout)
logger.addHandler(handler)

# Now initialize the client
credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://your-keyvault.vault.azure.net/", credential=credential)
```



## Azure Filestorage


# Azure Storage File DataLake Python Package Reference Card

## 1. Overview

The `azure-storage-file-datalake` package provides a Python client library for Azure Data Lake Storage Gen2, allowing you to work with Azure Data Lake Storage using a hierarchical file system interface.

## 2. Installation

```bash
pip install azure-storage-file-datalake
```

## 3. Key Components

### 3.1 Service Client

`DataLakeServiceClient`: Entry point for service-level operations like creating and managing file systems.

### 3.2 File System Client

`DataLakeFileSystemClient`: Manages operations on a specific file system (container).

### 3.3 Directory Client

`DataLakeDirectoryClient`: Handles operations related to directories within a file system.

### 3.4 File Client

`DataLakeFileClient`: Manages file-specific operations.

## 4. Authentication Methods

### 4.1 Connection String

```python
from azure.storage.filedatalake import DataLakeServiceClient

service_client = DataLakeServiceClient.from_connection_string(
    "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net"
)
```

### 4.2 Account Key

```python
from azure.storage.filedatalake import DataLakeServiceClient

service_client = DataLakeServiceClient(
    account_url="https://accountname.dfs.core.windows.net",
    credential="account_key"
)
```

### 4.3 Shared Access Signature (SAS)

```python
from azure.storage.filedatalake import DataLakeServiceClient

service_client = DataLakeServiceClient(
    account_url="https://accountname.dfs.core.windows.net",
    credential="sas_token"
)
```

### 4.4 Azure Active Directory (AAD)

```python
from azure.storage.filedatalake import DataLakeServiceClient
from azure.identity import DefaultAzureCredential

service_client = DataLakeServiceClient(
    account_url="https://accountname.dfs.core.windows.net",
    credential=DefaultAzureCredential()
)
```

## 5. Basic Operations

### 5.1 Managing File Systems (Containers)

```python
# Create a file system
file_system_client = service_client.create_file_system(file_system="myfilesystem")

# List file systems
file_systems = service_client.list_file_systems()
for file_system in file_systems:
    print(file_system.name)

# Get a file system client
file_system_client = service_client.get_file_system_client("myfilesystem")

# Delete a file system
file_system_client.delete_file_system()
```

### 5.2 Directory Operations

```python
# Create a directory
directory_client = file_system_client.create_directory("mydirectory")

# Create a directory with subdirectories
directory_client = file_system_client.create_directory("parent/child/grandchild")

# Get a directory client
directory_client = file_system_client.get_directory_client("mydirectory")

# List directory contents
paths = file_system_client.get_paths(path="mydirectory")
for path in paths:
    print(path.name, "is_directory:", path.is_directory)

# Rename a directory
new_directory_client = directory_client.rename_directory("new_directory_name")

# Delete a directory
directory_client.delete_directory()
```

### 5.3 File Operations

```python
# Create a file
file_client = directory_client.create_file("myfile.txt")

# Upload data to a file
data = b"Hello, World!"
file_client.append_data(data, 0, len(data))
file_client.flush_data(len(data))

# Alternative simpler way to upload
with open("local_file.txt", "rb") as file:
    file_client = directory_client.get_file_client("myfile.txt")
    file_client.upload_data(file, overwrite=True)

# Download a file
download = file_client.download_file()
content = download.readall()

# Download to a local file
with open("downloaded_file.txt", "wb") as file:
    download = file_client.download_file()
    file.write(download.readall())

# Get file properties
properties = file_client.get_file_properties()

# Delete a file
file_client.delete_file()
```

## 6. Advanced Operations

### 6.1 Access Control Lists (ACLs)

```python
# Get ACL for a directory
acl = directory_client.get_access_control()

# Set ACL for a directory
directory_client.set_access_control(
    permissions='rwxr-x---',
    acl={
        'user': {'id': 'user1', 'permissions': 'rwx'},
        'group': {'id': 'group1', 'permissions': 'r-x'}
    }
)

# Update ACL recursively
directory_client.update_access_control_recursive(acl={
    'user': {'id': 'user1', 'permissions': 'rwx'},
    'group': {'id': 'group1', 'permissions': 'r-x'}
})
```

### 6.2 Leases

```python
# Acquire a lease
lease_client = file_client.get_lease_client()
lease_id = lease_client.acquire(lease_duration=15)

# Renew a lease
lease_client.renew()

# Release a lease
lease_client.release()

# Break a lease
lease_client.break_lease()
```

### 6.3 Metadata Management

```python
# Set metadata
file_client.set_metadata({"key1": "value1", "key2": "value2"})

# Get metadata
metadata = file_client.get_file_properties().metadata
```

### 6.4 Batch Operations with Checkpoint Mode

```python
from azure.storage.filedatalake import ContentSettings, DirectoryProperties
from azure.core.exceptions import ResourceExistsError

# Batch upload files with checkpoint mode
def upload_batch_with_checkpoint(source_dir, target_dir_client):
    import os
    for root, dirs, files in os.walk(source_dir):
        for file_name in files:
            local_file = os.path.join(root, file_name)
            relative_path = os.path.relpath(local_file, source_dir)
            file_client = target_dir_client.get_file_client(relative_path)
            
            try:
                # Upload file with checkpoint mode
                with open(local_file, 'rb') as data:
                    file_client.upload_data(
                        data, 
                        overwrite=True,
                        max_concurrency=4,
                        checkpoint_mode="enabled",
                        chunk_size=4*1024*1024  # 4 MiB chunks
                    )
            except Exception as e:
                print(f"Error uploading {local_file}: {e}")
```

### 6.5 Resumable Upload

```python
from azure.storage.filedatalake import DataLakeFileClient, DataLakeServiceClient
import os

def resumable_upload(file_path, datalake_file_client):
    # Get file size
    file_size = os.path.getsize(file_path)
    
    # Chunk size: 4 MiB
    chunk_size = 4 * 1024 * 1024
    
    # Open file for reading
    with open(file_path, 'rb') as file:
        # Create the file if it doesn't exist
        try:
            datalake_file_client.create_file()
        except ResourceExistsError:
            # File already exists, get current length
            properties = datalake_file_client.get_file_properties()
            current_length = properties.size
            
            # Seek to current position
            file.seek(current_length)
        else:
            current_length = 0
        
        # Upload the file in chunks
        while current_length < file_size:
            # Read a chunk
            data = file.read(chunk_size)
            if not data:
                break
                
            # Upload the chunk
            datalake_file_client.append_data(data, current_length, len(data))
            current_length += len(data)
        
        # Flush the data
        datalake_file_client.flush_data(current_length)
```

## 7. Performance Optimization

### 7.1 Concurrent Operations

```python
# Parallel file upload
from concurrent.futures import ThreadPoolExecutor
import os

def upload_file(file_path, directory_client):
    file_name = os.path.basename(file_path)
    file_client = directory_client.get_file_client(file_name)
    with open(file_path, 'rb') as data:
        file_client.upload_data(data, overwrite=True)
    return file_name

def parallel_upload(local_dir, directory_client, max_workers=10):
    file_paths = [os.path.join(local_dir, f) for f in os.listdir(local_dir) 
                 if os.path.isfile(os.path.join(local_dir, f))]
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(
            lambda file_path: upload_file(file_path, directory_client), 
            file_paths
        )
        
    return list(results)
```

### 7.2 Configuring Retry Policies

```python
from azure.storage.filedatalake import DataLakeServiceClient
from azure.core.pipeline.policies import RetryPolicy

# Configure custom retry policy
retry_policy = RetryPolicy(retry_total=10, retry_mode="fixed", retry_backoff_factor=0.5)

# Apply custom policies
service_client = DataLakeServiceClient(
    account_url="https://accountname.dfs.core.windows.net",
    credential="account_key",
    retry_policy=retry_policy
)
```

### 7.3 Using Async Operations

```python
import asyncio
from azure.storage.filedatalake.aio import DataLakeServiceClient

async def list_file_systems_async():
    service_client = DataLakeServiceClient(
        account_url="https://accountname.dfs.core.windows.net",
        credential="account_key"
    )
    
    async with service_client:
        file_systems = []
        async for file_system in service_client.list_file_systems():
            file_systems.append(file_system.name)
    
    return file_systems

# Run the async function
file_systems = asyncio.run(list_file_systems_async())
```

## 8. Error Handling

```python
from azure.core.exceptions import (
    ResourceExistsError, 
    ResourceNotFoundError,
    ClientAuthenticationError,
    ServiceRequestError,
    HttpResponseError
)

try:
    file_system_client = service_client.create_file_system("myfilesystem")
except ResourceExistsError:
    # Handle case where file system already exists
    file_system_client = service_client.get_file_system_client("myfilesystem")
except ClientAuthenticationError:
    # Handle authentication errors
    print("Authentication failed. Check your credentials.")
except ServiceRequestError:
    # Handle connectivity errors
    print("Service request failed. Check your network connection.")
except HttpResponseError as e:
    # Handle other HTTP errors
    print(f"HTTP error occurred: {e.message}")
```

## 9. Best Practices

1. **Authentication**: Use Azure AD authentication with managed identities for enhanced security.

2. **Hierarchical Namespace**: Organize data logically with a well-planned directory structure.

3. **Connection Reuse**: Create client objects once and reuse them across operations.

4. **Batch Operations**: Use batch operations for processing multiple files to reduce network overhead.

5. **Parallelization**: Parallelize operations for large data transfers using `ThreadPoolExecutor`.

6. **Chunked Transfers**: Use chunked transfers for large files to enable resumable operations.

7. **Error Handling**: Implement comprehensive error handling with specific exception types.

8. **Retries**: Configure appropriate retry policies for transient errors.

9. **Logging**: Enable logging to troubleshoot issues:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

10. **Cleanup Resources**: Always close connections and release resources when done.

11. **Use Async Operations**: For high-throughput applications, use async methods.

12. **Monitor Performance**: Use Azure metrics to monitor storage account performance.

## 10. Common Patterns

### 10.1 Recursive Directory Traversal

```python
def list_all_paths(file_system_client, directory_path=""):
    paths = []
    path_iterator = file_system_client.get_paths(path=directory_path, recursive=True)
    
    for path in path_iterator:
        paths.append(path.name)
    
    return paths
```

### 10.2 Copy Files Between Storage Accounts

```python
from azure.storage.filedatalake import DataLakeServiceClient

def copy_file_between_accounts(source_file_client, dest_file_system_client, dest_path):
    # Get source properties and metadata
    source_properties = source_file_client.get_file_properties()
    source_metadata = source_properties.metadata
    
    # Get SAS URL for the source file
    source_url = source_file_client.url + "?SAS_TOKEN"
    
    # Create destination file
    dest_file_client = dest_file_system_client.get_file_client(dest_path)
    
    # Start copy operation
    copy_props = dest_file_client.start_copy_from_url(source_url=source_url)
    
    # Copy metadata
    if source_metadata:
        dest_file_client.set_metadata(source_metadata)
    
    return copy_props
```

### 10.3 Folder/Directory Synchronization

```python
def sync_directories(source_dir_client, target_dir_client, prefix=""):
    # List paths in the source directory
    source_paths = list(source_dir_client.get_paths(recursive=True))
    
    # Process each path
    for path in source_paths:
        # Skip if it's a directory
        if path.is_directory:
            continue
            
        # Get relative path
        rel_path = path.name
        if prefix:
            rel_path = rel_path.replace(prefix, "", 1).lstrip('/')
            
        # Get source file client
        source_file_client = source_dir_client.get_file_client(rel_path)
        
        # Get or create target file client
        target_file_client = target_dir_client.get_file_client(rel_path)
        
        # Download source file
        download = source_file_client.download_file()
        content = download.readall()
        
        # Upload to target
        target_file_client.upload_data(content, overwrite=True)
```


## Azure Blob Storage


# Azure Storage Blob Python Package Cheat Sheet

## Installation and Setup

```python
# Install the package
pip install azure-storage-blob

# Basic imports
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
```

## Authentication Methods

### Connection String (simplest approach)
```python
# Connect using connection string
connection_string = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=accountkey;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connection_string)
```

### Account Key
```python
# Connect using account name and key
from azure.storage.blob import BlobServiceClient
account_url = "https://mystorageaccount.blob.core.windows.net"
account_key = "your_account_key"
blob_service_client = BlobServiceClient(account_url=account_url, credential=account_key)
```

### Azure Active Directory (AAD)
```python
# Using Azure Identity library
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

account_url = "https://mystorageaccount.blob.core.windows.net"
credential = DefaultAzureCredential()
blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)
```

### SAS Token
```python
# Using SAS token
from azure.storage.blob import BlobServiceClient

account_url = "https://mystorageaccount.blob.core.windows.net"
sas_token = "sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacupitfx&se=2023-11-04T14:56:21Z&st=2023-11-04T06:56:21Z&spr=https&sig=..."
blob_service_client = BlobServiceClient(account_url=account_url, credential=sas_token)
```

## Container Operations

### Create a container
```python
# Create a new container
container_name = "mycontainer"
try:
    container_client = blob_service_client.create_container(container_name)
    print(f"Container '{container_name}' created")
except ResourceExistsError:
    print(f"Container '{container_name}' already exists")
    container_client = blob_service_client.get_container_client(container_name)
```

### List containers
```python
# List containers in the storage account
containers = blob_service_client.list_containers()
for container in containers:
    print(container.name)
```

### Get container properties
```python
# Get container properties
container_client = blob_service_client.get_container_client(container_name)
properties = container_client.get_container_properties()
print(f"Container etag: {properties.etag}")
print(f"Container last_modified: {properties.last_modified}")
```

### Delete a container
```python
# Delete a container
container_client = blob_service_client.get_container_client(container_name)
container_client.delete_container()
print(f"Container '{container_name}' deleted")
```

## Blob Operations

### Upload blob
```python
# Upload a blob from a local file
container_client = blob_service_client.get_container_client(container_name)
blob_name = "my-blob.txt"
local_file_path = "path/to/local/file.txt"

# Upload from file path
with open(local_file_path, "rb") as data:
    container_client.upload_blob(name=blob_name, data=data, overwrite=True)

# Upload from bytes directly
blob_data = b"Hello, Azure Blob Storage!"
container_client.upload_blob(name="sample.txt", data=blob_data, overwrite=True)
```

### Get a Blob Client
```python
# Get a blob client
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

# Alternative: from container client
container_client = blob_service_client.get_container_client(container_name)
blob_client = container_client.get_blob_client(blob=blob_name)
```

### Download blob
```python
# Download a blob to a local file
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
with open("downloaded_file.txt", "wb") as download_file:
    download_file.write(blob_client.download_blob().readall())

# Download to a stream
from io import BytesIO
stream = BytesIO()
blob_client.download_blob().readinto(stream)
# Process the stream data
stream.seek(0)  # Reset stream position for reading
content = stream.read()
```

### List blobs
```python
# List blobs in a container
container_client = blob_service_client.get_container_client(container_name)
blob_list = container_client.list_blobs()
for blob in blob_list:
    print(f"Blob name: {blob.name}, Size: {blob.size} bytes")

# List blobs with a specific prefix
blobs_with_prefix = container_client.list_blobs(name_starts_with="folder1/")
for blob in blobs_with_prefix:
    print(f"Blob name: {blob.name}")
```

### Check if a blob exists
```python
# Check if blob exists
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
try:
    blob_properties = blob_client.get_blob_properties()
    print(f"Blob exists. Size: {blob_properties.size} bytes")
    exists = True
except ResourceNotFoundError:
    print("Blob does not exist")
    exists = False
```

### Copy blob
```python
# Copy a blob within the same storage account
source_blob_client = blob_service_client.get_blob_client(container=source_container, blob=source_blob)
destination_blob_client = blob_service_client.get_blob_client(container=destination_container, blob=destination_blob)

# Get the source URL with SAS token (if needed for auth)
from datetime import datetime, timedelta
sas_token = source_blob_client.generate_shared_access_signature(
    permission="r",
    expiry=datetime.utcnow() + timedelta(hours=1)
)
source_url = source_blob_client.url + "?" + sas_token

# Start the copy operation (simpler if both blobs are in same storage account with same auth)
copy = destination_blob_client.start_copy_from_url(source_url)
print(f"Copy operation ID: {copy['copy_id']}")
```

### Delete blob
```python
# Delete a blob
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
blob_client.delete_blob()
print(f"Blob '{blob_name}' deleted")
```

## Blob Metadata and Properties

### Set and retrieve metadata
```python
# Set blob metadata
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
metadata = {'category': 'documents', 'department': 'finance'}
blob_client.set_blob_metadata(metadata)

# Get blob metadata
properties = blob_client.get_blob_properties()
metadata = properties.metadata
print(f"Blob metadata: {metadata}")
```

### Update blob properties
```python
# Update blob properties like content type
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
blob_client.set_http_headers(content_type="application/json", content_encoding="gzip")

# Get blob properties
properties = blob_client.get_blob_properties()
print(f"Content type: {properties.content_settings.content_type}")
```

## Advanced Features

### Leases
```python
# Acquire a lease on a blob (prevent other clients from modifying)
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
lease_duration = 60  # in seconds, or -1 for infinite
lease_id = blob_client.acquire_lease(lease_duration=lease_duration)

try:
    # Perform operations with the lease
    blob_client.upload_blob(data=b"New content", lease=lease_id, overwrite=True)
finally:
    # Release the lease when done
    blob_client.release_lease(lease=lease_id)
```

### Append Blobs
```python
# Create an append blob
from azure.storage.blob import AppendBlobClient

append_blob_client = AppendBlobClient.from_connection_string(
    connection_string, container_name, "append-blob.txt")

# Create the append blob
append_blob_client.create_append_blob()

# Append data to the blob
append_blob_client.append_block(b"First line\n")
append_blob_client.append_block(b"Second line\n")
```

### Block Blobs (Staging/Committing)
```python
# Upload a large file in blocks
from azure.storage.blob import BlobClient
import uuid

blob_client = BlobClient.from_connection_string(
    connection_string, container_name, "large-file.txt")

# Define block size and get the local file size
block_size = 4 * 1024 * 1024  # 4 MiB
import os
file_size = os.path.getsize(local_file_path)

# Generate block IDs
block_ids = []

# Upload file in blocks
with open(local_file_path, "rb") as data:
    for i in range(0, file_size, block_size):
        block_id = str(uuid.uuid4())
        block_ids.append(block_id)
        
        # Read and upload a block
        data_chunk = data.read(block_size)
        blob_client.stage_block(block_id=block_id, data=data_chunk)
        
        print(f"Uploaded block {len(block_ids)} with ID {block_id}")

# Commit the blocks
blob_client.commit_block_list(block_ids)
print("Blob upload complete")
```

### Page Blobs
```python
# Create page blob (useful for random access scenarios like virtual disks)
from azure.storage.blob import PageBlobClient

# Create a 1 MiB page blob
page_blob_client = PageBlobClient.from_connection_string(
    connection_string, container_name, "page-blob.vhd")

page_size = 512  # Page blobs must be aligned to 512-byte boundaries
page_blob_client.create_page_blob(size=1024*1024)  # 1 MiB size

# Write to specific page
data = b"A" * page_size
page_blob_client.upload_pages(data, offset=0, length=page_size)

# Clear pages
page_blob_client.clear_pages(offset=0, length=page_size)
```

### Blob Snapshots
```python
# Create a snapshot of a blob
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
snapshot = blob_client.create_snapshot()
snapshot_id = snapshot['snapshot']
print(f"Created snapshot with ID: {snapshot_id}")

# Access the snapshot
snapshot_client = blob_service_client.get_blob_client(
    container=container_name, 
    blob=blob_name,
    snapshot=snapshot_id
)

# Download the snapshot
with open("snapshot_download.txt", "wb") as download_file:
    download_file.write(snapshot_client.download_blob().readall())
```

### Soft Delete
```python
# Enable soft delete for the storage account (can be done in Azure Portal)
# Then, recover a deleted blob within the retention period
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

# List deleted blobs
container_client = blob_service_client.get_container_client(container_name)
deleted_blobs = container_client.list_blobs(include=['deleted'])

for blob in deleted_blobs:
    if blob.name == blob_name:
        # Undelete the blob
        blob_client.undelete_blob()
        print(f"Blob '{blob_name}' restored")
```

### Access Tiers
```python
# Set access tier when uploading
container_client = blob_service_client.get_container_client(container_name)
container_client.upload_blob(
    name=blob_name, 
    data=b"Example content", 
    standard_blob_tier="Hot"  # Options: "Hot", "Cool", "Archive"
)

# Change access tier of existing blob
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
blob_client.set_standard_blob_tier("Cool")
```

### Batch Operations
```python
# Execute operations in batch
from azure.storage.blob.batch import BlobBatchClient
from azure.storage.blob import generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta

# Create a batch client
batch_client = BlobBatchClient(account_url=account_url, credential=credential)

# Delete multiple blobs in a single request
delete_batch = []
blobs_to_delete = ["blob1.txt", "blob2.txt", "blob3.txt"]
for blob_name in blobs_to_delete:
    delete_batch.append(container_name + "/" + blob_name)

batch_client.delete_blobs(*delete_batch)
```

### Handle large result sets (pagination)
```python
# Handle large result sets using continuation tokens
container_client = blob_service_client.get_container_client(container_name)
result = container_client.list_blobs(results_per_page=100)

# First page of results
for blob in result:
    print(f"Blob name: {blob.name}")

# Get additional pages
while result.continuation_token:
    result = container_client.list_blobs(
        results_per_page=100, 
        continuation_token=result.continuation_token
    )
    for blob in result:
        print(f"Blob name: {blob.name}")
```

### Async Operations
```python
# Using the async library
from azure.storage.blob.aio import BlobServiceClient
import asyncio

async def upload_blob_async():
    # Create the client
    async with BlobServiceClient.from_connection_string(connection_string) as blob_service_client:
        container_client = blob_service_client.get_container_client(container_name)
        
        # Upload a blob
        blob_client = container_client.get_blob_client("async-blob.txt")
        await blob_client.upload_blob(b"Async content", overwrite=True)
        print("Upload complete")

# Run the async function
asyncio.run(upload_blob_async())
```

## Best Practices and Tips

### Error Handling
```python
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError, ClientAuthenticationError

try:
    # Your blob operation
    blob_client.upload_blob(data=data, overwrite=False)
except ResourceExistsError:
    print("Blob already exists and overwrite is False")
except ResourceNotFoundError:
    print("Container or blob not found")
except ClientAuthenticationError:
    print("Authentication failed. Check your credentials")
except Exception as e:
    print(f"An error occurred: {str(e)}")
```

### Retry Policies
```python
# Custom retry policy
from azure.storage.blob import BlobServiceClient
from azure.core.pipeline.policies import RetryPolicy

# Create custom retry policy with more retries for transient failures
custom_retry = RetryPolicy(retry_total=10, retry_connect=5, retry_read=5)

# Apply to client
blob_service_client = BlobServiceClient.from_connection_string(
    conn_str=connection_string,
    retry_policy=custom_retry
)
```

### Performance Optimization
```python
# Parallel uploads for large files
from concurrent.futures import ThreadPoolExecutor
import os

def upload_block(args):
    blob_client, block_id, data = args
    blob_client.stage_block(block_id=block_id, data=data)
    return block_id

# Upload large file in parallel
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
block_size = 4 * 1024 * 1024  # 4 MiB
file_size = os.path.getsize(local_file_path)

blocks = []
block_ids = []

# Read file and prepare blocks
with open(local_file_path, "rb") as file:
    block_num = 0
    while True:
        read_data = file.read(block_size)
        if not read_data:
            break
        
        # Create block ID and add to list
        block_id = f"{block_num:08d}"
        block_ids.append(block_id)
        blocks.append((blob_client, block_id, read_data))
        block_num += 1

# Upload blocks in parallel
with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(upload_block, blocks)

# Commit all blocks
blob_client.commit_block_list(block_ids)
```

### Security - Generating SAS Tokens
```python
# Generate a SAS token for a blob
from datetime import datetime, timedelta
from azure.storage.blob import generate_blob_sas, BlobSasPermissions

# Set permissions and expiry
permissions = BlobSasPermissions(read=True, write=True)
expiry = datetime.utcnow() + timedelta(hours=1)

# Generate SAS token
sas_token = generate_blob_sas(
    account_name=account_name,
    container_name=container_name,
    blob_name=blob_name,
    account_key=account_key,
    permission=permissions,
    expiry=expiry
)

# Create URL with SAS token
sas_url = f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_token}"
print(f"SAS URL: {sas_url}")
```

### Logging
```python
# Set up logging for Azure Storage operations
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# Enable Azure Storage logging
logger = logging.getLogger('azure.storage')
logger.setLevel(logging.DEBUG)

# Create a file handler
handler = logging.FileHandler('azure_storage.log')
handler.setLevel(logging.DEBUG)

# Add the handler to the logger
logger.addHandler(handler)
```

### Blob Versioning
```python
# When versioning is enabled on the storage account, 
# each blob operation creates a new version automatically

# List all versions of a blob
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
versions = container_client.list_blobs(name_starts_with=blob_name, include=['versions'])

for version in versions:
    if version.name == blob_name:
        print(f"Version ID: {version.version_id}, Last Modified: {version.last_modified}")

# Access a specific version
version_id = "2023-11-05T14:56:21.1234567Z"
version_blob_client = blob_service_client.get_blob_client(
    container=container_name,
    blob=blob_name,
    version_id=version_id
)

# Download a specific version
with open(f"version_{version_id}.txt", "wb") as download_file:
    download_file.write(version_blob_client.download_blob().readall())
```


## Azure Machine Learning

# Azure Machine Learning Python SDK Reference Card

## Core Components

### Workspace
```python
# Initialize workspace
from azureml.core import Workspace

ws = Workspace.from_config()  # Uses config.json in current directory
# Or create/get directly
ws = Workspace.create(
    name='myworkspace',
    subscription_id='<subscription_id>',
    resource_group='myresourcegroup',
    create_resource_group=True,
    location='eastus'
)
```

### Experiments
```python
from azureml.core import Experiment

# Create an experiment
experiment = Experiment(workspace=ws, name="my-experiment")

# Start a run
run = experiment.start_logging()
run.log("accuracy", 0.95)  # Log metrics
run.complete()  # End the run
```

### Environment
```python
from azureml.core import Environment

# Create from pip requirements
env = Environment.from_pip_requirements("my-env", "requirements.txt")

# Create from conda
env = Environment.from_conda_specification("my-env", "conda.yml")

# Use curated environment
env = Environment.get(ws, name="AzureML-TensorFlow-2.4-GPU")
```

### Compute
```python
from azureml.core.compute import ComputeTarget, AmlCompute

# Create compute cluster
compute_config = AmlCompute.provisioning_configuration(
    vm_size='STANDARD_NC6',
    min_nodes=0,
    max_nodes=4,
    idle_seconds_before_scaledown=1800
)
compute = ComputeTarget.create(ws, "gpu-cluster", compute_config)
compute.wait_for_completion(show_output=True)

# List compute resources
compute_targets = ws.compute_targets
```

### Datasets
```python
from azureml.core import Dataset

# Create tabular dataset
datastore = ws.get_default_datastore()
tabular_dataset = Dataset.Tabular.from_delimited_files(
    path=(datastore, 'path/to/data.csv')
)

# Create file dataset
file_dataset = Dataset.File.from_files(
    path=(datastore, 'path/to/files/')
)

# Register datasets
tabular_dataset.register(ws, name='my-tabular-dataset')
file_dataset.register(ws, name='my-file-dataset')

# Get registered dataset
dataset = Dataset.get_by_name(ws, name='my-dataset')
```

## Training Models

### ScriptRunConfig (Classic SDK)
```python
from azureml.core import ScriptRunConfig
from azureml.core.runconfig import RunConfiguration

run_config = RunConfiguration()
run_config.environment = env

src = ScriptRunConfig(
    source_directory='./src',
    script='train.py',
    arguments=['--data', dataset.as_mount(), '--epochs', 50],
    compute_target=compute,
    runconfig=run_config
)

run = experiment.submit(src)
```

### Command (SDK v2)
```python
from azure.ai.ml import command
from azure.ai.ml.entities import Environment

# Define the command
job = command(
    code="./src",
    command="python train.py --data ${{inputs.data}} --epochs 50",
    inputs={
        "data": Input(type="uri_folder", path="azureml:my-dataset:1")
    },
    environment="AzureML-TensorFlow-2.4-GPU",
    compute="gpu-cluster"
)

# Submit the job
ml_client.jobs.create_or_update(job)
```

### Hyperparameter Tuning
```python
from azureml.train.hyperdrive import RandomParameterSampling, BanditPolicy
from azureml.train.hyperdrive import HyperDriveConfig, PrimaryMetricGoal
from azureml.train.hyperdrive import choice, uniform

# Define the parameter space
param_sampling = RandomParameterSampling({
    '--learning-rate': uniform(0.001, 0.1),
    '--batch-size': choice(32, 64, 128, 256)
})

# Define early termination policy
early_termination_policy = BanditPolicy(
    evaluation_interval=2,
    slack_factor=0.1
)

# Create HyperDrive config
hyperdrive_config = HyperDriveConfig(
    run_config=src,
    hyperparameter_sampling=param_sampling,
    policy=early_termination_policy,
    primary_metric_name="accuracy",
    primary_metric_goal=PrimaryMetricGoal.MAXIMIZE,
    max_total_runs=20,
    max_concurrent_runs=4
)

# Submit the experiment
hyperdrive_run = experiment.submit(hyperdrive_config)
```

## Model Management

### Register Model
```python
from azureml.core.model import Model

# Register model from run
model = run.register_model(
    model_name="my-model",
    model_path="outputs/model.pkl",
    description="My trained model",
    tags={"framework": "scikit-learn", "type": "classification"}
)

# Register model from file
model = Model.register(
    workspace=ws,
    model_path="./models/model.pkl",
    model_name="my-model",
    description="My trained model"
)

# List models
models = Model.list(ws)
```

### Deploy Model
```python
from azureml.core.webservice import AciWebservice, AksWebservice
from azureml.core.model import InferenceConfig

# Define inference config
inference_config = InferenceConfig(
    entry_script="score.py",
    environment=env
)

# Deploy to ACI (development)
aci_config = AciWebservice.deploy_configuration(
    cpu_cores=1,
    memory_gb=1,
    auth_enabled=True
)

aci_service = Model.deploy(
    workspace=ws,
    name="my-aci-service",
    models=[model],
    inference_config=inference_config,
    deployment_config=aci_config
)
aci_service.wait_for_deployment(show_output=True)

# Deploy to AKS (production)
aks_target = ComputeTarget(workspace=ws, name="my-aks-cluster")
aks_config = AksWebservice.deploy_configuration(
    autoscale_enabled=True,
    autoscale_min_replicas=1,
    autoscale_max_replicas=3,
    cpu_cores=1,
    memory_gb=2
)

aks_service = Model.deploy(
    workspace=ws,
    name="my-aks-service",
    models=[model],
    inference_config=inference_config,
    deployment_config=aks_config,
    deployment_target=aks_target
)
```

### MLflow Integration
```python
import mlflow
from azureml.core import Workspace

# Set MLflow tracking to AzureML workspace
ws = Workspace.from_config()
mlflow.set_tracking_uri(ws.get_mlflow_tracking_uri())

# Start MLflow run
mlflow.start_run()

# Log parameters
mlflow.log_param("learning_rate", 0.01)

# Log metrics
mlflow.log_metric("accuracy", 0.95)

# Log model
mlflow.sklearn.log_model(model, "model")

# End the run
mlflow.end_run()
```

## Advanced Features

### Azure ML Pipelines
```python
from azureml.pipeline.steps import PythonScriptStep
from azureml.pipeline.core import Pipeline

# Data prep step
data_prep_step = PythonScriptStep(
    name="data_prep",
    script_name="prep.py",
    compute_target=compute,
    source_directory="./src",
    outputs=[processed_data],
    arguments=["--output-dir", processed_data],
    runconfig=run_config
)

# Training step
train_step = PythonScriptStep(
    name="train",
    script_name="train.py",
    compute_target=compute,
    source_directory="./src",
    inputs=[processed_data],
    outputs=[model_output],
    arguments=["--data-dir", processed_data, "--output-dir", model_output],
    runconfig=run_config
)

# Create pipeline
pipeline = Pipeline(workspace=ws, steps=[data_prep_step, train_step])

# Submit pipeline
pipeline_run = experiment.submit(pipeline)

# Schedule pipeline recurrence
from azureml.pipeline.core import ScheduleRecurrence, Schedule

recurrence = ScheduleRecurrence(frequency="Day", interval=1)
schedule = Schedule.create(
    workspace=ws,
    name="daily-training",
    pipeline_id=pipeline.id,
    experiment_name=experiment.name,
    recurrence=recurrence
)
```

### AutoML
```python
from azureml.train.automl import AutoMLConfig
from azureml.train.automl.run import AutoMLRun

# Configure AutoML
automl_config = AutoMLConfig(
    task='classification',
    primary_metric='AUC_weighted',
    experiment_timeout_minutes=60,
    training_data=dataset,
    label_column_name='target',
    n_cross_validations=5,
    compute_target=compute,
    enable_early_stopping=True,
    featurization='auto',
    debug_log='automl_errors.log'
)

# Submit AutoML run
automl_run = experiment.submit(automl_config)

# Get best model
best_run, best_model = automl_run.get_output()
```

### Responsible AI
```python
from azureml.interpret import ExplanationClient
from interpret.ext.blackbox import TabularExplainer

# Create TabularExplainer
explainer = TabularExplainer(
    model,
    X_train,
    features=feature_names
)

# Compute feature importances
global_explanation = explainer.explain_global(X_test)

# Upload explanations
client = ExplanationClient.from_run(run)
client.upload_model_explanation(global_explanation)

# Generate fairness insights
from fairlearn.metrics import demographic_parity_difference
from azureml.contrib.fairness import upload_dashboard_dictionary

sensitive_features = X_test[['gender', 'age']]
y_pred = model.predict(X_test)

# Calculate fairness metrics
metric_dict = {
    'demographic_parity_difference': demographic_parity_difference(
        y_test, y_pred, sensitive_features=sensitive_features
    )
}

# Upload to AzureML dashboard
upload_dashboard_dictionary(run, metric_dict)
```

## Best Practices

### Project Structure
```
.
├── .azureml/                  # AzureML config files
├── data/                      # Data files
├── notebooks/                 # Jupyter notebooks for exploration
├── src/                       # Source code
│   ├── __init__.py
│   ├── prepare.py             # Data preparation
│   ├── train.py               # Model training
│   ├── score.py               # Model inference
│   └── utils.py               # Helper functions
├── tests/                     # Unit tests
├── config.json                # AzureML workspace config
├── environment.yml            # Conda environment definition
├── requirements.txt           # Python package requirements
└── README.md                  # Project documentation
```

### Tracking and Monitoring
```python
# Enable application insights for monitoring
from azureml.core.webservice import LocalWebservice

deployment_config = LocalWebservice.deploy_configuration(
    port=6789,
    enable_app_insights=True
)

# Log custom dimensions with App Insights
import logging
from opencensus.ext.azure.log_exporter import AzureLogHandler

logger = logging.getLogger(__name__)
logger.addHandler(
    AzureLogHandler(connection_string="InstrumentationKey=<key>")
)

# Log with custom dimensions
properties = {'custom_dimensions': {'model_version': '1.0.0', 'env': 'production'}}
logger.warning('Model drift detected', extra=properties)
```

### Optimization Techniques
```python
# Use DDP for distributed training
from azureml.core.runconfig import MpiConfiguration

# Configure distributed training
distributed_config = MpiConfiguration(
    process_count_per_node=4,
    node_count=2
)

run_config = RunConfiguration()
run_config.environment = env
run_config.mpi = distributed_config

# Use data caching for faster training
dataset = dataset.with_options(
    azureml.data.dataset_factory.DatasetFactory.with_options(cache=True)
)
```

### CI/CD Integration
```yaml
# Example Azure DevOps YAML pipeline
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.8'

- script: pip install -r requirements.txt
  displayName: 'Install dependencies'

- script: pytest tests/
  displayName: 'Run tests'

- script: |
    az login --service-principal -u $(AZURE_CLIENT_ID) -p $(AZURE_CLIENT_SECRET) --tenant $(AZURE_TENANT_ID)
    python deployment/deploy_model.py
  displayName: 'Deploy model'
  env:
    AZURE_CLIENT_ID: $(AZURE_CLIENT_ID)
    AZURE_CLIENT_SECRET: $(AZURE_CLIENT_SECRET)
    AZURE_TENANT_ID: $(AZURE_TENANT_ID)
```

### Security Practices
```python
# Use service principal for non-interactive authentication
from azureml.core.authentication import ServicePrincipalAuthentication

sp_auth = ServicePrincipalAuthentication(
    tenant_id="<tenant-id>",
    service_principal_id="<service-principal-id>",
    service_principal_password="<service-principal-password>"
)

ws = Workspace.get(
    name="myworkspace",
    subscription_id="<subscription-id>",
    resource_group="myresourcegroup",
    auth=sp_auth
)

# Enable network isolation for training
run_config = RunConfiguration()
run_config.environment = env
run_config.environment_variables = {"AZUREML_WORKSPACE_CONNECTION_ID_ENDPOINT": "stringValueHere"}
run_config.isolate_network = True
```





## Azure Kubernetes

# Python Azure Kubernetes Reference Card

## Azure Kubernetes Service (AKS) Fundamentals

### Setting Up Azure CLI and Python SDK

```python
# Install required libraries
pip install azure-identity azure-mgmt-containerservice azure-mgmt-resource

# Import key libraries
from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.resource import ResourceManagementClient
```

### Authentication

```python
# Authenticate using DefaultAzureCredential
credential = DefaultAzureCredential()

# Create clients
subscription_id = "your-subscription-id"
container_service_client = ContainerServiceClient(credential, subscription_id)
resource_client = ResourceManagementClient(credential, subscription_id)
```

### Creating Resource Group

```python
# Create a resource group
resource_group_name = "myAKSResourceGroup"
location = "eastus"

resource_client.resource_groups.create_or_update(
    resource_group_name,
    {"location": location}
)
```

### Basic AKS Cluster Creation

```python
# Define AKS configuration
aks_name = "myAKSCluster"
dns_prefix = "myakscluster"

# Create the AKS cluster
aks_creation = container_service_client.managed_clusters.begin_create_or_update(
    resource_group_name,
    aks_name,
    {
        "location": location,
        "dns_prefix": dns_prefix,
        "agent_pool_profiles": [{
            "name": "agentpool",
            "count": 3,
            "vm_size": "Standard_DS2_v2",
            "os_type": "Linux",
            "mode": "System"
        }],
        "service_principal_profile": {
            "client_id": "client-id",
            "secret": "client-secret"
        }
    }
)

aks_cluster = aks_creation.result()
```

### Get Kubernetes Credentials

```python
from azure.cli.core import get_default_cli

# Get credentials for kubectl
get_default_cli().invoke(['aks', 'get-credentials', 
                         '--resource-group', resource_group_name, 
                         '--name', aks_name])

# Alternatively, use the Python SDK
credentials = container_service_client.managed_clusters.list_cluster_user_credentials(
    resource_group_name,
    aks_name
)
```

## Python Kubernetes Client

### Setting Up Kubernetes Client

```python
# Install the client
pip install kubernetes

# Import key modules
from kubernetes import client, config

# Load kube config
config.load_kube_config()

# Create API clients
v1 = client.CoreV1Api()
apps_v1 = client.AppsV1Api()
```

### Basic Operations

```python
# List all pods in the cluster
pods = v1.list_pod_for_all_namespaces()
for pod in pods.items:
    print(f"{pod.metadata.namespace}\t{pod.metadata.name}")

# List all deployments
deployments = apps_v1.list_deployment_for_all_namespaces()
for deployment in deployments.items:
    print(f"{deployment.metadata.namespace}\t{deployment.metadata.name}")
```

### Creating Deployments

```python
# Create a deployment
deployment = client.V1Deployment(
    metadata=client.V1ObjectMeta(name="nginx-deployment"),
    spec=client.V1DeploymentSpec(
        replicas=3,
        selector=client.V1LabelSelector(
            match_labels={"app": "nginx"}
        ),
        template=client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(
                labels={"app": "nginx"}
            ),
            spec=client.V1PodSpec(
                containers=[
                    client.V1Container(
                        name="nginx",
                        image="nginx:1.19",
                        ports=[client.V1ContainerPort(container_port=80)]
                    )
                ]
            )
        )
    )
)

# Create the deployment
apps_v1.create_namespaced_deployment(
    namespace="default",
    body=deployment
)
```

### Creating Services

```python
# Create a service
service = client.V1Service(
    metadata=client.V1ObjectMeta(name="nginx-service"),
    spec=client.V1ServiceSpec(
        selector={"app": "nginx"},
        ports=[client.V1ServicePort(port=80, target_port=80)],
        type="LoadBalancer"
    )
)

# Create the service
v1.create_namespaced_service(
    namespace="default",
    body=service
)
```

## Advanced AKS Management

### Cluster Autoscaling

```python
# Enable cluster autoscaler
cluster_update = {
    "agent_pool_profiles": [{
        "name": "agentpool",
        "count": 3,
        "min_count": 1,
        "max_count": 10,
        "enable_auto_scaling": True,
        "vm_size": "Standard_DS2_v2",
        "os_type": "Linux",
        "mode": "System"
    }]
}

container_service_client.managed_clusters.begin_create_or_update(
    resource_group_name,
    aks_name,
    cluster_update
)
```

### Node Pool Management

```python
# Add a new node pool
node_pool = {
    "count": 2,
    "vm_size": "Standard_DS3_v2",
    "os_type": "Linux",
    "mode": "User"
}

container_service_client.agent_pools.begin_create_or_update(
    resource_group_name,
    aks_name,
    "userpool",
    node_pool
)
```

### Enabling Azure Monitor for Containers

```python
# Enable Azure Monitor
monitor_config = {
    "addon_profiles": {
        "omsagent": {
            "enabled": True
        }
    }
}

container_service_client.managed_clusters.begin_create_or_update(
    resource_group_name,
    aks_name,
    monitor_config
)
```

## Kubernetes Resource Management

### Configuring HPA (Horizontal Pod Autoscaler)

```python
# Create HPA
hpa = client.V1HorizontalPodAutoscaler(
    metadata=client.V1ObjectMeta(name="nginx-hpa"),
    spec=client.V1HorizontalPodAutoscalerSpec(
        scale_target_ref=client.V1CrossVersionObjectReference(
            kind="Deployment",
            name="nginx-deployment",
            api_version="apps/v1"
        ),
        min_replicas=1,
        max_replicas=10,
        target_cpu_utilization_percentage=80
    )
)

# Create the HPA
autoscaling_v1 = client.AutoscalingV1Api()
autoscaling_v1.create_namespaced_horizontal_pod_autoscaler(
    namespace="default",
    body=hpa
)
```

### Working with ConfigMaps and Secrets

```python
# Create a ConfigMap
config_map = client.V1ConfigMap(
    metadata=client.V1ObjectMeta(name="app-config"),
    data={"app.properties": "property1=value1\nproperty2=value2"}
)

v1.create_namespaced_config_map(
    namespace="default",
    body=config_map
)

# Create a Secret
import base64
secret = client.V1Secret(
    metadata=client.V1ObjectMeta(name="app-secret"),
    type="Opaque",
    data={
        "username": base64.b64encode(b"admin").decode(),
        "password": base64.b64encode(b"secure-password").decode()
    }
)

v1.create_namespaced_secret(
    namespace="default",
    body=secret
)
```

### Custom Resource Definitions (CRDs)

```python
# Working with CRDs
api_client = client.ApiClient()
custom_api = client.CustomObjectsApi(api_client)

# Get custom resources
custom_resources = custom_api.list_cluster_custom_object(
    group="example.com",
    version="v1",
    plural="customresources"
)

# Create custom resource
custom_resource = {
    "apiVersion": "example.com/v1",
    "kind": "CustomResource",
    "metadata": {
        "name": "my-custom-resource"
    },
    "spec": {
        "property1": "value1",
        "property2": "value2"
    }
}

custom_api.create_namespaced_custom_object(
    group="example.com",
    version="v1",
    namespace="default",
    plural="customresources",
    body=custom_resource
)
```

## CI/CD Integration

### Azure DevOps Pipeline Example

```yaml
# azure-pipelines.yml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

variables:
  imageName: 'myapp'
  imageTag: '$(Build.BuildId)'
  acrName: 'myacr'
  acrLoginServer: '$(acrName).azurecr.io'
  resourceGroupName: 'myAKSResourceGroup'
  aksClusterName: 'myAKSCluster'

steps:
- task: Docker@2
  inputs:
    containerRegistry: 'ACRConnection'
    repository: '$(imageName)'
    command: 'buildAndPush'
    Dockerfile: 'Dockerfile'
    tags: '$(imageTag)'

- task: AzureCLI@2
  inputs:
    azureSubscription: 'AzureServiceConnection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      az aks get-credentials --resource-group $(resourceGroupName) --name $(aksClusterName)
      
      # Update the image in Kubernetes deployment
      sed -i 's|image:.*|image: $(acrLoginServer)/$(imageName):$(imageTag)|' k8s/deployment.yaml
      
      kubectl apply -f k8s/deployment.yaml
```

### Python Script for CD

```python
# cd_script.py
import os
import subprocess
from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient

# Connect to AKS
credential = DefaultAzureCredential()
subscription_id = os.environ["SUBSCRIPTION_ID"]
resource_group = os.environ["RESOURCE_GROUP"]
aks_name = os.environ["AKS_NAME"]

# Get AKS credentials
client = ContainerServiceClient(credential, subscription_id)
command = f"az aks get-credentials --resource-group {resource_group} --name {aks_name} --overwrite-existing"
subprocess.run(command, shell=True, check=True)

# Update deployment
image = os.environ["ACR_SERVER"] + "/" + os.environ["IMAGE_NAME"] + ":" + os.environ["IMAGE_TAG"]
deploy_command = f"kubectl set image deployment/myapp myapp={image}"
subprocess.run(deploy_command, shell=True, check=True)

# Verify deployment
subprocess.run("kubectl rollout status deployment/myapp", shell=True, check=True)
```

## Best Practices

### Resource Management

- **Right-sizing containers**: Set appropriate resource requests and limits
```python
container = client.V1Container(
    name="app",
    image="app:latest",
    resources=client.V1ResourceRequirements(
        requests={"cpu": "100m", "memory": "128Mi"},
        limits={"cpu": "500m", "memory": "512Mi"}
    )
)
```

- **Use namespaces for logical separation**
```python
# Create namespace
namespace = client.V1Namespace(
    metadata=client.V1ObjectMeta(name="development")
)
v1.create_namespace(namespace)

# Deploy to specific namespace
apps_v1.create_namespaced_deployment(
    namespace="development",
    body=deployment
)
```

### Security Practices

- **Use managed identities instead of service principals**
```python
aks_config = {
    "location": location,
    "dns_prefix": dns_prefix,
    "identity": {
        "type": "SystemAssigned"
    },
    "agent_pool_profiles": [...]
}
```

- **Enable Azure Policy for AKS**
```python
policy_config = {
    "addon_profiles": {
        "azurepolicy": {
            "enabled": True
        }
    }
}
```

- **Network security with network policies**
```python
network_config = {
    "network_profile": {
        "network_plugin": "azure",
        "network_policy": "calico"
    }
}
```

### Monitoring and Logging

- **Set up Prometheus and Grafana**
```python
monitoring_config = {
    "addon_profiles": {
        "azuremonitor": {
            "enabled": True
        }
    }
}
```

- **Custom metrics collection**
```python
# Create ServiceMonitor (requires prometheus-operator)
service_monitor = {
    "apiVersion": "monitoring.coreos.com/v1",
    "kind": "ServiceMonitor",
    "metadata": {
        "name": "app-monitor",
        "namespace": "monitoring"
    },
    "spec": {
        "selector": {
            "matchLabels": {
                "app": "myapp"
            }
        },
        "endpoints": [
            {
                "port": "metrics",
                "interval": "15s"
            }
        ]
    }
}
```

### Disaster Recovery

- **Schedule regular backups with Velero**
```python
# Install Velero using Helm chart
from kubernetes import config
import subprocess

config.load_kube_config()
subprocess.run("helm install velero vmware-tanzu/velero --namespace velero --create-namespace", shell=True)

# Create backup with Python
backup = {
    "apiVersion": "velero.io/v1",
    "kind": "Backup",
    "metadata": {
        "name": "daily-backup",
        "namespace": "velero"
    },
    "spec": {
        "includedNamespaces": ["default"],
        "storageLocation": "default",
        "ttl": "720h"
    }
}

custom_api.create_namespaced_custom_object(
    group="velero.io",
    version="v1",
    namespace="velero",
    plural="backups",
    body=backup
)
```

## Performance Optimization

### Resource Optimization

- **Use node selectors and taints/tolerations for workload distribution**
```python
# Pod with node selector
pod = client.V1Pod(
    metadata=client.V1ObjectMeta(name="gpu-pod"),
    spec=client.V1PodSpec(
        containers=[...],
        node_selector={"accelerator": "nvidia"}
    )
)
```

- **Cluster Autoscaler Profiles**
```python
autoscaler_profile = {
    "auto_scaler_profile": {
        "scan_interval": "10s",
        "scale_down_delay_after_add": "10m",
        "scale_down_delay_after_delete": "10s",
        "scale_down_delay_after_failure": "3m",
        "scale_down_unneeded_time": "10m",
        "scale_down_unready_time": "20m"
    }
}
```

### Cost Optimization

- **Use node pool spot instances for batch processing**
```python
spot_node_pool = {
    "count": 3,
    "vm_size": "Standard_D2s_v3",
    "os_type": "Linux",
    "mode": "User",
    "spot_max_price": -1,  # Market price
    "priority": "Spot",
    "eviction_policy": "Delete"
}
```

- **Schedule scaling for predictable workloads using KEDA**
```python
# KEDA ScaledObject example
scaled_object = {
    "apiVersion": "keda.sh/v1alpha1",
    "kind": "ScaledObject",
    "metadata": {
        "name": "azure-queue-scaledobject",
        "namespace": "default"
    },
    "spec": {
        "scaleTargetRef": {
            "name": "azure-queue-consumer"
        },
        "pollingInterval": 30,
        "cooldownPeriod": 300,
        "minReplicaCount": 0,
        "maxReplicaCount": 30,
        "triggers": [
            {
                "type": "azure-queue",
                "metadata": {
                    "queueName": "myqueue",
                    "queueLength": "5"
                },
                "authenticationRef": {
                    "name": "azure-queue-auth"
                }
            }
        ]
    }
}
```




