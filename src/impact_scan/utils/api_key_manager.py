"""
API Key Management utilities with CRUD operations.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from enum import Enum
try:
    import keyring
    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False
    keyring = None
from pydantic import BaseModel, Field

from impact_scan.utils.schema import AIProvider


class StorageMethod(Enum):
    """Storage methods for API keys."""
    ENVIRONMENT = "environment"
    KEYRING = "keyring" 
    FILE = "file"


class APIKeyEntry(BaseModel):
    """Individual API key entry with metadata."""
    provider: AIProvider
    key: str = Field(..., min_length=1)
    name: Optional[str] = None  # User-friendly name
    created_at: Optional[str] = None
    last_used: Optional[str] = None
    is_active: bool = True


class APIKeyManager:
    """Manages CRUD operations for API keys across different providers."""
    
    def __init__(self, storage_method: StorageMethod = StorageMethod.ENVIRONMENT):
        self.storage_method = storage_method
        self.config_dir = Path.home() / ".impact-scan"
        self.config_file = self.config_dir / "api_keys.json"
        self.service_name = "impact-scan"
        
        # Ensure config directory exists for file storage
        if storage_method == StorageMethod.FILE:
            self.config_dir.mkdir(exist_ok=True)
    
    def create_key(self, provider: AIProvider, key: str, name: Optional[str] = None) -> bool:
        """Create a new API key for a provider."""
        try:
            entry = APIKeyEntry(
                provider=provider,
                key=key,
                name=name or f"{provider.value.title()} Key",
                created_at=self._get_timestamp(),
                is_active=True
            )
            
            return self._store_key(entry)
        except Exception as e:
            print(f"Error creating key for {provider.value}: {e}")
            return False
    
    def read_key(self, provider: AIProvider) -> Optional[str]:
        """Read API key for a provider."""
        try:
            if self.storage_method == StorageMethod.ENVIRONMENT:
                return self._get_env_key(provider)
            elif self.storage_method == StorageMethod.KEYRING:
                if not HAS_KEYRING:
                    raise ValueError("Keyring not available. Install with: pip install keyring")
                return keyring.get_password(self.service_name, provider.value)
            elif self.storage_method == StorageMethod.FILE:
                return self._get_file_key(provider)
        except Exception as e:
            print(f"Error reading key for {provider.value}: {e}")
            return None
    
    def read_all_keys(self) -> Dict[AIProvider, Optional[str]]:
        """Read all API keys."""
        keys = {}
        for provider in AIProvider:
            keys[provider] = self.read_key(provider)
        return keys
    
    def update_key(self, provider: AIProvider, key: str, name: Optional[str] = None) -> bool:
        """Update existing API key for a provider."""
        try:
            # For environment and keyring, this is the same as create
            if self.storage_method in [StorageMethod.ENVIRONMENT, StorageMethod.KEYRING]:
                return self.create_key(provider, key, name)
            
            # For file storage, preserve metadata
            elif self.storage_method == StorageMethod.FILE:
                entries = self._load_file_entries()
                
                # Find existing entry or create new one
                updated = False
                for entry in entries:
                    if entry.provider == provider:
                        entry.key = key
                        if name:
                            entry.name = name
                        entry.last_used = self._get_timestamp()
                        updated = True
                        break
                
                if not updated:
                    # Create new entry if not found
                    entries.append(APIKeyEntry(
                        provider=provider,
                        key=key,
                        name=name or f"{provider.value.title()} Key",
                        created_at=self._get_timestamp(),
                        is_active=True
                    ))
                
                return self._save_file_entries(entries)
                
        except Exception as e:
            print(f"Error updating key for {provider.value}: {e}")
            return False
    
    def delete_key(self, provider: AIProvider) -> bool:
        """Delete API key for a provider."""
        try:
            if self.storage_method == StorageMethod.ENVIRONMENT:
                env_var = self._get_env_var_name(provider)
                if env_var in os.environ:
                    del os.environ[env_var]
                return True
                
            elif self.storage_method == StorageMethod.KEYRING:
                if not HAS_KEYRING:
                    raise ValueError("Keyring not available. Install with: pip install keyring")
                keyring.delete_password(self.service_name, provider.value)
                return True
                
            elif self.storage_method == StorageMethod.FILE:
                entries = self._load_file_entries()
                entries = [e for e in entries if e.provider != provider]
                return self._save_file_entries(entries)
                
        except Exception as e:
            print(f"Error deleting key for {provider.value}: {e}")
            return False
    
    def list_providers(self) -> List[Tuple[AIProvider, bool, Optional[str]]]:
        """List all providers with their status and names."""
        results = []
        for provider in AIProvider:
            key = self.read_key(provider)
            has_key = key is not None and len(key) > 0
            
            # Get name if using file storage
            name = None
            if self.storage_method == StorageMethod.FILE:
                entries = self._load_file_entries()
                for entry in entries:
                    if entry.provider == provider:
                        name = entry.name
                        break
            
            results.append((provider, has_key, name))
        
        return results
    
    def test_key(self, provider: AIProvider) -> Tuple[bool, str]:
        """Test if an API key is valid for a provider."""
        key = self.read_key(provider)
        if not key:
            return False, "No API key found"
        
        try:
            if provider == AIProvider.OPENAI:
                return self._test_openai_key(key)
            elif provider == AIProvider.ANTHROPIC:
                return self._test_anthropic_key(key)
            elif provider == AIProvider.GEMINI:
                return self._test_gemini_key(key)
            else:
                return False, "Provider not supported"
                
        except Exception as e:
            return False, f"Test failed: {e}"
    
    def clear_all_keys(self) -> bool:
        """Clear all API keys."""
        try:
            for provider in AIProvider:
                self.delete_key(provider)
            return True
        except Exception as e:
            print(f"Error clearing all keys: {e}")
            return False
    
    def _store_key(self, entry: APIKeyEntry) -> bool:
        """Store API key based on storage method."""
        if self.storage_method == StorageMethod.ENVIRONMENT:
            env_var = self._get_env_var_name(entry.provider)
            os.environ[env_var] = entry.key
            return True
            
        elif self.storage_method == StorageMethod.KEYRING:
            if not HAS_KEYRING:
                raise ValueError("Keyring not available. Install with: pip install keyring")
            keyring.set_password(self.service_name, entry.provider.value, entry.key)
            return True
            
        elif self.storage_method == StorageMethod.FILE:
            entries = self._load_file_entries()
            
            # Remove existing entry for this provider
            entries = [e for e in entries if e.provider != entry.provider]
            
            # Add new entry
            entries.append(entry)
            
            return self._save_file_entries(entries)
    
    def _get_env_key(self, provider: AIProvider) -> Optional[str]:
        """Get API key from environment variable."""
        env_var = self._get_env_var_name(provider)
        return os.getenv(env_var)
    
    def _get_env_var_name(self, provider: AIProvider) -> str:
        """Get environment variable name for provider."""
        mapping = {
            AIProvider.OPENAI: "OPENAI_API_KEY",
            AIProvider.ANTHROPIC: "ANTHROPIC_API_KEY", 
            AIProvider.GEMINI: "GOOGLE_API_KEY"
        }
        return mapping.get(provider, f"{provider.value.upper()}_API_KEY")
    
    def _get_file_key(self, provider: AIProvider) -> Optional[str]:
        """Get API key from file storage."""
        entries = self._load_file_entries()
        for entry in entries:
            if entry.provider == provider and entry.is_active:
                return entry.key
        return None
    
    def _load_file_entries(self) -> List[APIKeyEntry]:
        """Load API key entries from file."""
        if not self.config_file.exists():
            return []
        
        try:
            with open(self.config_file, 'r') as f:
                data = json.load(f)
                return [APIKeyEntry(**item) for item in data]
        except Exception as e:
            print(f"Error loading API keys from file: {e}")
            return []
    
    def _save_file_entries(self, entries: List[APIKeyEntry]) -> bool:
        """Save API key entries to file."""
        try:
            data = [entry.dict() for entry in entries]
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error saving API keys to file: {e}")
            return False
    
    def _get_timestamp(self) -> str:
        """Get current timestamp as string."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _test_openai_key(self, key: str) -> Tuple[bool, str]:
        """Test OpenAI API key."""
        try:
            import openai
            client = openai.OpenAI(api_key=key)
            # Simple test call
            models = client.models.list()
            return True, "OpenAI key is valid"
        except Exception as e:
            return False, f"OpenAI test failed: {e}"
    
    def _test_anthropic_key(self, key: str) -> Tuple[bool, str]:
        """Test Anthropic API key."""
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=key)
            # Test with a minimal message
            response = client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=1,
                messages=[{"role": "user", "content": "Hi"}]
            )
            return True, "Anthropic key is valid"
        except Exception as e:
            return False, f"Anthropic test failed: {e}"
    
    def _test_gemini_key(self, key: str) -> Tuple[bool, str]:
        """Test Gemini API key."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=key)
            model = genai.GenerativeModel('gemini-pro')
            response = model.generate_content("Hi", 
                generation_config=genai.types.GenerationConfig(max_output_tokens=1))
            return True, "Gemini key is valid"
        except Exception as e:
            return False, f"Gemini test failed: {e}"


# Convenience functions
def get_api_key_manager() -> APIKeyManager:
    """Get configured API key manager instance."""
    return APIKeyManager(StorageMethod.ENVIRONMENT)  # Default to environment


def create_api_key(provider: AIProvider, key: str, name: Optional[str] = None) -> bool:
    """Create API key for provider."""
    manager = get_api_key_manager()
    return manager.create_key(provider, key, name)


def get_api_key(provider: AIProvider) -> Optional[str]:
    """Get API key for provider."""
    manager = get_api_key_manager()
    return manager.read_key(provider)


def update_api_key(provider: AIProvider, key: str, name: Optional[str] = None) -> bool:
    """Update API key for provider."""
    manager = get_api_key_manager()
    return manager.update_key(provider, key, name)


def delete_api_key(provider: AIProvider) -> bool:
    """Delete API key for provider."""
    manager = get_api_key_manager()
    return manager.delete_key(provider)


def list_api_keys() -> List[Tuple[AIProvider, bool, Optional[str]]]:
    """List all API keys with status."""
    manager = get_api_key_manager()
    return manager.list_providers()


def test_api_key(provider: AIProvider) -> Tuple[bool, str]:
    """Test API key for provider."""
    manager = get_api_key_manager()
    return manager.test_key(provider)