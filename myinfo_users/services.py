import logging
from typing import Dict, Optional, Tuple

from django.conf import settings
from django.core.cache import cache
from django.utils.crypto import get_random_string

from myinfo.client import MyInfoPersonalClientV4

logger = logging.getLogger(__name__)


class MyInfoService:
    """
    Service to handle MyInfo API integration
    """

    @staticmethod
    def generate_state() -> str:
        """
        Generate a random state string for OAuth flow
        """
        return get_random_string(length=16)

    @staticmethod
    def get_authorize_url(state: str, callback_url: Optional[str] = None) -> str:
        """
        Get MyInfo authorize URL
        """
        callback = callback_url or settings.MYINFO_CALLBACK_URL
        client = MyInfoPersonalClientV4()
        return client.get_authorise_url(state, callback)

    @staticmethod
    def store_state(state: str, ttl: int = 600) -> None:
        """
        Store state in cache with TTL (default 10 minutes)
        """
        cache_key = f'myinfo:state:{state}'
        cache.set(cache_key, True, ttl)

    @staticmethod
    def verify_state(state: str) -> bool:
        """
        Verify if state exists in cache
        """
        cache_key = f'myinfo:state:{state}'
        return cache.get(cache_key) is not None

    @staticmethod
    def delete_state(state: str) -> None:
        """
        Delete state from cache
        """
        cache_key = f'myinfo:state:{state}'
        cache.delete(cache_key)

    @staticmethod
    def store_session_keys(state: str, keypair) -> None:
        """
        Store session ephemeral keypair with state
        """
        cache_key = f'myinfo:keys:{state}'
        # Store private key as JSON string
        cache.set(cache_key, keypair.export_private(), 600)  # 10 minutes TTL

    @staticmethod
    def get_session_keys(state: str):
        """
        Get session ephemeral keypair for state
        """
        from jwcrypto import jwk
        cache_key = f'myinfo:keys:{state}'
        key_json = cache.get(cache_key)
        if not key_json:
            return None
        return jwk.JWK.from_json(key_json)

    @classmethod
    def retrieve_person_data(cls, auth_code: str, state: str, callback_url: Optional[str] = None) -> Tuple[Dict, bool]:
        """
        Retrieve person data from MyInfo

        Returns:
            Tuple[Dict, bool]: Person data and success flag
        """
        client = MyInfoPersonalClientV4()
        callback = callback_url or settings.MYINFO_CALLBACK_URL

        # Verify state
        if not cls.verify_state(state):
            logger.error(f"Invalid state: {state}")
            return {"error": "Invalid state parameter"}, False

        try:
            # Generate ephemeral keypair
            person_data = client.retrieve_resource(auth_code, state, callback)
            return person_data, True
        except Exception as e:
            logger.exception(f"Error retrieving person data: {e}")
            return {"error": str(e)}, False
        finally:
            # Clean up state
            cls.delete_state(state)

    @classmethod
    def initiate_myinfo_flow(cls, callback_url: Optional[str] = None) -> Dict:
        """
        Initiate MyInfo authentication flow

        Returns:
            Dict with state and authorize URL
        """
        state = cls.generate_state()
        callback = callback_url or settings.MYINFO_CALLBACK_URL

        # Store state in cache
        cls.store_state(state)

        # Get authorize URL
        authorize_url = cls.get_authorize_url(state, callback)

        return {
            "state": state,
            "authorize_url": authorize_url
        }
