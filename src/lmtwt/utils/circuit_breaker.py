"""
Circuit breaker pattern implementation for handling API rate limits and errors.
"""
import time
import logging
from functools import wraps
from typing import Callable, Dict, Any, Optional, TypeVar, Generic

# Type variable for the return type of the function
T = TypeVar('T')

class CircuitBreaker:
    """
    Circuit breaker implementation for handling API rate limits and errors.
    
    The circuit breaker has three states:
    - CLOSED: Normal operation, calls pass through
    - OPEN: Circuit is broken, calls fail fast without calling the service
    - HALF-OPEN: After cooling period, allows a test call to see if service is healthy
    """
    
    # Circuit states
    CLOSED = 'CLOSED'
    OPEN = 'OPEN'
    HALF_OPEN = 'HALF_OPEN'
    
    def __init__(
        self, 
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: int = 60,
        expected_exceptions: tuple = (Exception,),
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the circuit breaker.
        
        Args:
            name: Name of the circuit (for logging)
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before trying again (half-open state)
            expected_exceptions: Tuple of exceptions that should trigger the circuit
            logger: Optional logger instance
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exceptions = expected_exceptions
        self.logger = logger or logging.getLogger(__name__)
        
        # State tracking
        self.state = self.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0
        self.error_message = None
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """
        Decorator to wrap a function with circuit breaker functionality.
        
        Args:
            func: The function to wrap
            
        Returns:
            Wrapped function with circuit breaker logic
        """
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self._call(func, *args, **kwargs)
        return wrapper
    
    def _call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute the wrapped function with circuit breaker logic.
        
        Args:
            func: Function to call
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func
            
        Returns:
            Result of func call
            
        Raises:
            CircuitBreakerError: If circuit is open
        """
        # Check if circuit is open
        if self.state == self.OPEN:
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                # Recovery timeout reached, try half-open state
                self.logger.info(f"Circuit '{self.name}' entering HALF-OPEN state")
                self.state = self.HALF_OPEN
            else:
                # Circuit still open, fail fast
                remaining = int(self.recovery_timeout - (time.time() - self.last_failure_time))
                raise CircuitBreakerError(
                    f"Circuit '{self.name}' is OPEN. Retry in {remaining}s. Last error: {self.error_message}"
                )
        
        try:
            # Call the function
            result = func(*args, **kwargs)
            
            # If successful in half-open state, close the circuit
            if self.state == self.HALF_OPEN:
                self.logger.info(f"Circuit '{self.name}' test call successful, closing circuit")
                self._close()
            
            return result
        
        except self.expected_exceptions as e:
            # Handle expected exceptions
            self.error_message = str(e)
            self.last_failure_time = time.time()
            
            # Rate limit check - if it's a rate limit error, open immediately
            is_rate_limit = any(
                error_str in str(e).lower() for error_str in 
                ['rate limit', 'quota exceeded', '429', 'too many requests']
            )
            
            if is_rate_limit:
                # Open circuit immediately for rate limit errors
                self.logger.warning(
                    f"Rate limit detected in circuit '{self.name}', opening circuit. Error: {e}"
                )
                self._open()
            else:
                # Increment failure count
                self.failure_count += 1
                
                # Check if threshold reached
                if self.state == self.CLOSED and self.failure_count >= self.failure_threshold:
                    self.logger.warning(
                        f"Circuit '{self.name}' failure threshold reached, opening circuit. Error: {e}"
                    )
                    self._open()
                elif self.state == self.HALF_OPEN:
                    self.logger.warning(
                        f"Circuit '{self.name}' test call failed, keeping circuit open. Error: {e}"
                    )
                    self._open()
                else:
                    self.logger.info(
                        f"Circuit '{self.name}' failure count: {self.failure_count}/{self.failure_threshold}. Error: {e}"
                    )
            
            # Re-raise the exception
            raise
    
    def _open(self):
        """Open the circuit."""
        self.state = self.OPEN
        self.failure_count = 0
    
    def _close(self):
        """Close the circuit."""
        self.state = self.CLOSED
        self.failure_count = 0
        self.error_message = None
    
    def get_state(self) -> Dict[str, Any]:
        """
        Get the current state of the circuit breaker.
        
        Returns:
            Dictionary with state information
        """
        return {
            'name': self.name,
            'state': self.state,
            'failure_count': self.failure_count,
            'last_failure_time': self.last_failure_time,
            'error_message': self.error_message,
            'recovery_remaining': max(0, int(self.recovery_timeout - (time.time() - self.last_failure_time))) 
                if self.state == self.OPEN else 0
        }


class CircuitBreakerError(Exception):
    """Error raised when a circuit is open."""
    pass


def with_fallback(fallback_func: Callable[..., T]) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to provide a fallback function when a circuit is open.
    
    Args:
        fallback_func: Function to call when circuit is open
        
    Returns:
        Decorator function that wraps the original function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            try:
                return func(*args, **kwargs)
            except CircuitBreakerError as e:
                return fallback_func(*args, error=str(e), **kwargs)
        return wrapper
    return decorator 