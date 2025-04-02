# If was putting in devlopment or if had more time would have modify the lock system to track both admin username
# and session/IP to prevent the same admin from multiple browsers/sessions from accessing simultaneously.
# Import required threading and time utilities
from threading import Lock  # For thread-safe locking mechanism
from time import time      # For timestamp management
from collections import defaultdict  # For automatic lock creation
# The difference from dictionary is, It provides a default value for the key that does not exist and never raises a KeyError.
import logging

# Logging configuration
logger = logging.getLogger(__name__)

class LockManager:
    def __init__(self):
        self._locks = defaultdict(Lock) # Dictionary to store Lock objects for each resource
        self._lock_info = {}  # Dictionary to store metadata about active locks
        self._cleanup_lock = Lock() # Lock for thread-safe access to _lock_info, (cleanup operations)
        self.LOCK_TIMEOUT = 301 # 5 minutes and one second

    def cleanup_stale_locks(self):
        try:
            # Remove locks that are older than the timeout period
            current_time = time()
            with self._cleanup_lock:  # update lock information
                stale_locks = []
                for resource_id, info in self._lock_info.items():  # Iterate over all lock info
                    lock_age = current_time - info['timestamp']  # Calculate the age of the lock
                    if lock_age > self.LOCK_TIMEOUT:  # Check if the lock has expired
                        stale_locks.append(resource_id)  # Add to the list of stale locks
                for resource_id in stale_locks:
                    self._locks[resource_id].release()  # Release stale locks
                    del self._lock_info[resource_id]  # Remove stale lock information
                    logger.info(f"Released stale lock for resource {resource_id}")
        except Exception as e:
            logger.critical(f"Error during cleanup of stale locks: {e}", exc_info=True)

    def acquire_lock(self, resource_id, admin_id, timeout=5):
        try:
            if not resource_id or not admin_id:
                logger.error("Invalid resource_id or admin_id")
                return False
                
            if timeout <= 0:
                logger.error("Invalid timeout value")
                return False
            
            self.cleanup_stale_locks()  # Cleanup before acquiring new lock
            lock = self._locks[resource_id]  # Get or create a Lock object
            if lock.acquire(timeout=timeout):  # Try to acquire the lock with timeout
                # Critical section - update lock information
                with self._cleanup_lock:  # Update lock information
                    self._lock_info[resource_id] = {
                        'admin_id': admin_id,  # Who holds the lock
                        'timestamp': time()  # When the lock was acquired
                    }
                logger.info(f"Lock acquired for resource {resource_id} by admin {admin_id}")
                return True
            logger.warning(f"Failed to acquire lock for resource {resource_id} by admin {admin_id}")
            return False
        except Exception as e:
            logger.error(f"Error during lock acquisition for resource {resource_id} by admin {admin_id}: {e}", exc_info=True)
            return False

    def release_lock(self, resource_id, admin_id):
        try:
            # Critical section - check and update lock information
            with self._cleanup_lock:
                if resource_id in self._lock_info:
                    if self._lock_info[resource_id]['admin_id'] == admin_id:  # Verify the admin requesting release owns the lock
                        self._locks[resource_id].release()  # Release the Lock
                        del self._lock_info[resource_id]  # Remove the lock information
                        logger.info(f"Lock released for resource {resource_id} by admin {admin_id}")
                        return True
            return False
        except Exception as e:
            logger.error(f"Error during lock release for resource {resource_id} by admin {admin_id}: {e}", exc_info=True)
            return False

    def is_locked(self, resource_id):
        try:
            self.cleanup_stale_locks()  # Cleanup before checking lock status
            # Simple check for existence of lock info
            return resource_id in self._lock_info
        except Exception as e:
            logger.error(f"Error checking lock status for resource {resource_id}: {e}", exc_info=True)
            return False

    def get_lock_holder(self, resource_id):
        try:
            return self._lock_info.get(resource_id, {}).get('admin_id')  # Safely retrieve lock holder info, return None if not found
        except Exception as e:
            logger.error(f"Error retrieving lock holder for resource {resource_id}: {e}", exc_info=True)
            return None

# Create a global instance for app-wide use
lock_manager = LockManager()
