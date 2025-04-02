import random
import time
import logging

logger = logging.getLogger(__name__)

def random_delay(min_ms=1, max_ms=5):
    try:
        # Handle invalid inputs by using default values
        if min_ms < 0 or min_ms > max_ms:
            logger.warning(f"Invalid min_ms ({min_ms}), using default value of 1")
            min_ms = 1
        if max_ms < 0 or max_ms < min_ms:
            logger.warning(f"Invalid max_ms ({max_ms}), using default value of 5")
            max_ms = 5
            
        delay = random.uniform(min_ms / 1000, max_ms / 1000)
        time.sleep(delay)
    except Exception as e:
        logger.error(f"Error during random delay: {str(e)}")
        # Use minimum delay as fallback
        time.sleep(0.001)
