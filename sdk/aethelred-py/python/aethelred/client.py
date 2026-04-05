"""
Aethelred Client

Enterprise-grade client for interacting with the Aethelred Sovereign AI Platform.
Provides high-level APIs for compute job submission, seal management, and
network operations.

Example:
    >>> from aethelred import AethelredClient, Network
    >>>
    >>> client = AethelredClient(
    ...     network=Network.TESTNET,
    ...     api_key="your-api-key",
    ... )
    >>>
    >>> # Submit a compute job
    >>> job = await client.submit_job(
    ...     model_id="credit-score-v1",
    ...     input_data=encrypted_data,
    ...     proof_type="hybrid",
    ... )
    >>>
    >>> # Wait for seal
    >>> seal = await client.wait_for_seal(job.id)
    >>> print(f"Seal: {seal.id}")
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    TypeVar,
    Union,
)

from .exceptions import (
    AethelredError,
    ConnectionError,
    InvalidCredentialsError,
    InvalidInputError,
    ModelNotFoundError,
    RPCError,
    SealNotFoundError,
    TimeoutError,
    TransactionError,
)


# =============================================================================
# Network Configuration
# =============================================================================

class Network(Enum):
    """
    Available Aethelred networks.

    Example:
        >>> client = AethelredClient(network=Network.MAINNET)
    """

    # Production mainnet
    MAINNET = "mainnet"

    # Public testnet
    TESTNET = "testnet"

    # Development network (local)
    DEVNET = "devnet"

    # Custom network
    CUSTOM = "custom"

    @property
    def rpc_url(self) -> str:
        """Get the default RPC URL for this network."""
        urls = {
            Network.MAINNET: "https://rpc.mainnet.aethelred.io",
            Network.TESTNET: "https://rpc.testnet.aethelred.io",
            Network.DEVNET: "http://localhost:26657",
            Network.CUSTOM: "",
        }
        return urls.get(self, "")

    @property
    def api_url(self) -> str:
        """Get the default API URL for this network."""
        urls = {
            Network.MAINNET: "https://api.mainnet.aethelred.io",
            Network.TESTNET: "https://api.testnet.aethelred.io",
            Network.DEVNET: "http://localhost:1317",
            Network.CUSTOM: "",
        }
        return urls.get(self, "")

    @property
    def chain_id(self) -> str:
        """Get the chain ID for this network."""
        chain_ids = {
            Network.MAINNET: "aethelred-mainnet-1",
            Network.TESTNET: "aethelred-testnet-1",
            Network.DEVNET: "aethelred-devnet",
            Network.CUSTOM: "",
        }
        return chain_ids.get(self, "")

    @property
    def explorer_url(self) -> str:
        """Get the block explorer URL for this network."""
        urls = {
            Network.MAINNET: "https://explorer.aethelred.io",
            Network.TESTNET: "https://explorer.testnet.aethelred.io",
            Network.DEVNET: "http://localhost:3000",
            Network.CUSTOM: "",
        }
        return urls.get(self, "")


@dataclass
class NetworkConfig:
    """
    Network configuration for custom networks.

    Example:
        >>> config = NetworkConfig(
        ...     rpc_url="https://my-node.example.com:26657",
        ...     api_url="https://my-node.example.com:1317",
        ...     chain_id="my-chain-1",
        ... )
        >>> client = AethelredClient(network_config=config)
    """

    rpc_url: str
    api_url: str
    chain_id: str
    explorer_url: Optional[str] = None
    grpc_url: Optional[str] = None
    websocket_url: Optional[str] = None

    @classmethod
    def from_env(cls) -> NetworkConfig:
        """Create config from environment variables."""
        return cls(
            rpc_url=os.environ.get("AETHELRED_RPC_URL", ""),
            api_url=os.environ.get("AETHELRED_API_URL", ""),
            chain_id=os.environ.get("AETHELRED_CHAIN_ID", ""),
            explorer_url=os.environ.get("AETHELRED_EXPLORER_URL"),
            grpc_url=os.environ.get("AETHELRED_GRPC_URL"),
            websocket_url=os.environ.get("AETHELRED_WS_URL"),
        )


# =============================================================================
# Data Types
# =============================================================================

@dataclass
class AccountInfo:
    """Account information."""

    address: str
    balance: int
    sequence: int
    account_number: int
    public_key: Optional[str] = None


@dataclass
class BlockInfo:
    """Block information."""

    height: int
    hash: str
    timestamp: datetime
    proposer: str
    num_txs: int


@dataclass
class ValidatorInfo:
    """Validator information."""

    address: str
    voting_power: int
    moniker: str
    commission: float
    hardware_type: str
    uptime: float
    seals_produced: int


@dataclass
class ComputeJobRequest:
    """
    Request for a compute job.

    Example:
        >>> job_request = ComputeJobRequest(
        ...     model_id="credit-score-v1",
        ...     input_hash="abc123...",
        ...     proof_type="hybrid",
        ...     priority=JobPriority.HIGH,
        ... )
    """

    model_id: str
    input_hash: str
    proof_type: str = "tee"  # "tee", "zkml", "hybrid"
    priority: int = 1  # 1=low, 2=normal, 3=high
    timeout_seconds: int = 300
    metadata: Dict[str, str] = field(default_factory=dict)


class JobStatus(Enum):
    """Compute job status."""

    PENDING = "pending"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ComputeJob:
    """
    A compute job submitted to the network.
    """

    id: str
    model_id: str
    input_hash: str
    output_hash: Optional[str]
    status: JobStatus
    created_at: datetime
    completed_at: Optional[datetime]
    block_height: Optional[int]
    seal_id: Optional[str]
    validator: Optional[str]
    proof_type: str
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DigitalSealInfo:
    """
    Digital seal information.
    """

    id: str
    model_commitment: str
    input_commitment: str
    output_commitment: str
    timestamp: datetime
    block_height: int
    validator_set: List[str]
    tee_attestations: List[Dict[str, Any]]
    zk_proof: Optional[Dict[str, Any]]
    regulatory_info: Dict[str, Any]


@dataclass
class ModelInfo:
    """
    Model registry information.
    """

    id: str
    name: str
    version: str
    hash: str
    framework: str
    architecture: str
    supported_proof_types: List[str]
    min_security_level: int
    registered_at: datetime
    owner: str
    compliance: List[str]


@dataclass
class TransactionResult:
    """
    Transaction result.
    """

    hash: str
    height: int
    code: int
    gas_used: int
    gas_wanted: int
    events: List[Dict[str, Any]]
    raw_log: str

    @property
    def success(self) -> bool:
        """Check if transaction was successful."""
        return self.code == 0


# =============================================================================
# Retry Policy
# =============================================================================

@dataclass
class RetryPolicy:
    """
    Retry policy for operations.

    Example:
        >>> policy = RetryPolicy(
        ...     max_retries=5,
        ...     initial_delay=1.0,
        ...     max_delay=60.0,
        ...     exponential_base=2.0,
        ... )
    """

    max_retries: int = 3
    initial_delay: float = 1.0
    max_delay: float = 30.0
    exponential_base: float = 2.0
    jitter: float = 0.1

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for a given attempt."""
        import random

        delay = min(
            self.initial_delay * (self.exponential_base ** attempt),
            self.max_delay,
        )
        jitter = delay * self.jitter * random.random()
        return delay + jitter


# =============================================================================
# Client Configuration
# =============================================================================

@dataclass
class ClientConfig:
    """
    Client configuration options.

    Example:
        >>> config = ClientConfig(
        ...     timeout=30.0,
        ...     retry_policy=RetryPolicy(max_retries=5),
        ...     enable_caching=True,
        ... )
        >>> client = AethelredClient(config=config)
    """

    # Request timeout in seconds
    timeout: float = 30.0

    # Retry policy for failed requests
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)

    # Enable response caching
    enable_caching: bool = True

    # Cache TTL in seconds
    cache_ttl: float = 60.0

    # Enable request logging
    enable_logging: bool = True

    # Enable metrics collection
    enable_metrics: bool = True

    # Connection pool size
    pool_size: int = 10

    # Keep-alive timeout
    keepalive: float = 30.0

    # SSL verification
    verify_ssl: bool = True

    # Custom headers
    headers: Dict[str, str] = field(default_factory=dict)


# =============================================================================
# HTTP Transport Layer
# =============================================================================

T = TypeVar("T")


class HTTPTransport(ABC):
    """Abstract HTTP transport interface."""

    @abstractmethod
    async def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """GET request."""
        pass

    @abstractmethod
    async def post(self, path: str, data: Any) -> Any:
        """POST request."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the transport."""
        pass


class DefaultHTTPTransport(HTTPTransport):
    """
    Default HTTP transport using aiohttp.

    Falls back to synchronous requests if aiohttp is not available.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        config: Optional[ClientConfig] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.config = config or ClientConfig()
        self._session = None
        self._closed = False

    async def _get_session(self):
        """Get or create HTTP session."""
        if self._session is None:
            try:
                import aiohttp

                headers = {"Content-Type": "application/json"}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"
                headers.update(self.config.headers)

                timeout = aiohttp.ClientTimeout(total=self.config.timeout)
                connector = aiohttp.TCPConnector(
                    limit=self.config.pool_size,
                    keepalive_timeout=self.config.keepalive,
                    ssl=self.config.verify_ssl,
                )
                self._session = aiohttp.ClientSession(
                    headers=headers,
                    timeout=timeout,
                    connector=connector,
                )
            except ImportError:
                # Fall back to synchronous requests
                self._session = None
        return self._session

    async def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Make GET request."""
        url = f"{self.base_url}{path}"

        session = await self._get_session()
        if session:
            async with session.get(url, params=params) as response:
                if response.status >= 400:
                    raise RPCError(
                        f"HTTP {response.status}: {await response.text()}",
                        method=f"GET {path}",
                        rpc_code=response.status,
                    )
                return await response.json()
        else:
            # Synchronous fallback
            import urllib.request
            import urllib.parse

            if params:
                url = f"{url}?{urllib.parse.urlencode(params)}"

            req = urllib.request.Request(url)
            req.add_header("Content-Type", "application/json")
            if self.api_key:
                req.add_header("Authorization", f"Bearer {self.api_key}")

            with urllib.request.urlopen(req, timeout=self.config.timeout) as response:
                return json.loads(response.read().decode())

    async def post(self, path: str, data: Any) -> Any:
        """Make POST request."""
        url = f"{self.base_url}{path}"

        session = await self._get_session()
        if session:
            async with session.post(url, json=data) as response:
                if response.status >= 400:
                    raise RPCError(
                        f"HTTP {response.status}: {await response.text()}",
                        method=f"POST {path}",
                        rpc_code=response.status,
                    )
                return await response.json()
        else:
            # Synchronous fallback
            import urllib.request

            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode(),
                method="POST",
            )
            req.add_header("Content-Type", "application/json")
            if self.api_key:
                req.add_header("Authorization", f"Bearer {self.api_key}")

            with urllib.request.urlopen(req, timeout=self.config.timeout) as response:
                return json.loads(response.read().decode())

    async def close(self) -> None:
        """Close the transport."""
        if self._session and not self._closed:
            await self._session.close()
            self._closed = True


# =============================================================================
# Cache Layer
# =============================================================================

@dataclass
class CacheEntry(Generic[T]):
    """Cache entry with TTL."""

    value: T
    expires_at: float


class AsyncCache(Generic[T]):
    """
    Simple async-safe LRU cache with TTL.
    """

    def __init__(self, max_size: int = 1000, ttl: float = 60.0):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, CacheEntry[T]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[T]:
        """Get value from cache."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if time.time() > entry.expires_at:
                del self._cache[key]
                return None
            return entry.value

    async def set(self, key: str, value: T, ttl: Optional[float] = None) -> None:
        """Set value in cache."""
        async with self._lock:
            if len(self._cache) >= self.max_size:
                # Evict oldest entry
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]

            self._cache[key] = CacheEntry(
                value=value,
                expires_at=time.time() + (ttl or self.ttl),
            )

    async def delete(self, key: str) -> None:
        """Delete value from cache."""
        async with self._lock:
            self._cache.pop(key, None)

    async def clear(self) -> None:
        """Clear all cached values."""
        async with self._lock:
            self._cache.clear()


# =============================================================================
# Metrics Collector
# =============================================================================

@dataclass
class RequestMetrics:
    """Metrics for a single request."""

    method: str
    path: str
    status_code: int
    duration_ms: float
    timestamp: datetime


class MetricsCollector:
    """
    Collects client metrics for monitoring.
    """

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._requests: List[RequestMetrics] = []
        self._total_requests = 0
        self._failed_requests = 0
        self._total_duration_ms = 0.0

    def record_request(
        self,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
    ) -> None:
        """Record a request metric."""
        self._total_requests += 1
        self._total_duration_ms += duration_ms
        if status_code >= 400:
            self._failed_requests += 1

        self._requests.append(
            RequestMetrics(
                method=method,
                path=path,
                status_code=status_code,
                duration_ms=duration_ms,
                timestamp=datetime.utcnow(),
            )
        )

        # Trim history
        if len(self._requests) > self.max_history:
            self._requests = self._requests[-self.max_history :]

    @property
    def total_requests(self) -> int:
        """Total number of requests."""
        return self._total_requests

    @property
    def failed_requests(self) -> int:
        """Number of failed requests."""
        return self._failed_requests

    @property
    def success_rate(self) -> float:
        """Success rate (0-1)."""
        if self._total_requests == 0:
            return 1.0
        return 1.0 - (self._failed_requests / self._total_requests)

    @property
    def average_latency_ms(self) -> float:
        """Average request latency in milliseconds."""
        if self._total_requests == 0:
            return 0.0
        return self._total_duration_ms / self._total_requests

    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        return {
            "total_requests": self._total_requests,
            "failed_requests": self._failed_requests,
            "success_rate": self.success_rate,
            "average_latency_ms": self.average_latency_ms,
        }


# =============================================================================
# Main Client Class
# =============================================================================

class AethelredClient:
    """
    Enterprise-grade client for the Aethelred Sovereign AI Platform.

    Provides high-level APIs for:
    - Compute job submission and monitoring
    - Digital seal management
    - Model registry operations
    - Network queries
    - Account management

    Example:
        >>> from aethelred import AethelredClient, Network
        >>>
        >>> # Create client
        >>> client = AethelredClient(
        ...     network=Network.TESTNET,
        ...     api_key="your-api-key",
        ... )
        >>>
        >>> # Submit a compute job
        >>> async with client:
        ...     job = await client.submit_job(
        ...         model_id="credit-score-v1",
        ...         input_data=encrypted_data,
        ...     )
        ...     seal = await client.wait_for_seal(job.id)
        ...     print(f"Verified! Seal: {seal.id}")
    """

    def __init__(
        self,
        network: Network = Network.TESTNET,
        network_config: Optional[NetworkConfig] = None,
        api_key: Optional[str] = None,
        config: Optional[ClientConfig] = None,
    ):
        """
        Initialize the client.

        Args:
            network: Network to connect to
            network_config: Custom network configuration (for CUSTOM network)
            api_key: API key for authentication
            config: Client configuration options
        """
        self.network = network
        self.config = config or ClientConfig()

        # Resolve network configuration
        if network == Network.CUSTOM:
            if network_config is None:
                network_config = NetworkConfig.from_env()
            self._network_config = network_config
        else:
            self._network_config = NetworkConfig(
                rpc_url=network.rpc_url,
                api_url=network.api_url,
                chain_id=network.chain_id,
                explorer_url=network.explorer_url,
            )

        # API key from env if not provided
        self.api_key = api_key or os.environ.get("AETHELRED_API_KEY")

        # Initialize components
        self._transport = DefaultHTTPTransport(
            base_url=self._network_config.api_url,
            api_key=self.api_key,
            config=self.config,
        )
        self._cache = AsyncCache(ttl=self.config.cache_ttl)
        self._metrics = MetricsCollector()
        self._closed = False

    async def __aenter__(self) -> AethelredClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close the client and release resources."""
        if not self._closed:
            await self._transport.close()
            await self._cache.clear()
            self._closed = True

    def _check_closed(self) -> None:
        """Check if client is closed."""
        if self._closed:
            raise RuntimeError("Client is closed")

    # -------------------------------------------------------------------------
    # Network Operations
    # -------------------------------------------------------------------------

    async def get_status(self) -> Dict[str, Any]:
        """
        Get network status.

        Returns:
            Network status information including:
            - latest_block_height
            - latest_block_time
            - chain_id
            - validator_count
            - syncing
        """
        self._check_closed()
        return await self._transport.get("/status")

    async def get_block(self, height: Optional[int] = None) -> BlockInfo:
        """
        Get block information.

        Args:
            height: Block height (latest if None)

        Returns:
            Block information
        """
        self._check_closed()

        path = f"/blocks/{height}" if height else "/blocks/latest"
        data = await self._transport.get(path)

        return BlockInfo(
            height=data["block"]["header"]["height"],
            hash=data["block_id"]["hash"],
            timestamp=datetime.fromisoformat(
                data["block"]["header"]["time"].replace("Z", "+00:00")
            ),
            proposer=data["block"]["header"]["proposer_address"],
            num_txs=len(data["block"]["data"].get("txs", [])),
        )

    async def get_validators(self) -> List[ValidatorInfo]:
        """
        Get list of active validators.

        Returns:
            List of validator information
        """
        self._check_closed()

        data = await self._transport.get("/validators")
        validators = []

        for v in data.get("validators", []):
            validators.append(
                ValidatorInfo(
                    address=v["operator_address"],
                    voting_power=int(v["voting_power"]),
                    moniker=v.get("description", {}).get("moniker", ""),
                    commission=float(v.get("commission", {}).get("rate", 0)),
                    hardware_type=v.get("hardware_type", "unknown"),
                    uptime=float(v.get("uptime", 0)),
                    seals_produced=int(v.get("seals_produced", 0)),
                )
            )

        return validators

    async def wait_for_block(
        self,
        target_height: int,
        timeout: float = 60.0,
        poll_interval: float = 1.0,
    ) -> BlockInfo:
        """
        Wait for a specific block height.

        Args:
            target_height: Target block height
            timeout: Maximum wait time in seconds
            poll_interval: Polling interval in seconds

        Returns:
            Block information when target height is reached

        Raises:
            TimeoutError: If target height not reached within timeout
        """
        self._check_closed()

        start_time = time.time()
        while time.time() - start_time < timeout:
            block = await self.get_block()
            if block.height >= target_height:
                return block
            await asyncio.sleep(poll_interval)

        raise TimeoutError(
            f"Block {target_height} not reached within {timeout}s",
            operation="wait_for_block",
            timeout_seconds=timeout,
        )

    # -------------------------------------------------------------------------
    # Account Operations
    # -------------------------------------------------------------------------

    async def get_account(self, address: str) -> AccountInfo:
        """
        Get account information.

        Args:
            address: Account address

        Returns:
            Account information
        """
        self._check_closed()

        data = await self._transport.get(f"/accounts/{address}")
        account = data.get("account", {})

        return AccountInfo(
            address=address,
            balance=int(account.get("balance", 0)),
            sequence=int(account.get("sequence", 0)),
            account_number=int(account.get("account_number", 0)),
            public_key=account.get("public_key"),
        )

    async def get_balance(self, address: str) -> int:
        """
        Get account balance in AETHEL (smallest unit).

        Args:
            address: Account address

        Returns:
            Balance in smallest units
        """
        account = await self.get_account(address)
        return account.balance

    # -------------------------------------------------------------------------
    # Compute Job Operations
    # -------------------------------------------------------------------------

    async def submit_job(
        self,
        model_id: str,
        input_data: bytes,
        proof_type: str = "tee",
        priority: int = 1,
        timeout_seconds: int = 300,
        metadata: Optional[Dict[str, str]] = None,
    ) -> ComputeJob:
        """
        Submit a compute job for verification.

        Args:
            model_id: Model identifier in the registry
            input_data: Input data (encrypted)
            proof_type: Proof type ("tee", "zkml", "hybrid")
            priority: Job priority (1=low, 2=normal, 3=high)
            timeout_seconds: Maximum execution time
            metadata: Optional metadata

        Returns:
            Submitted compute job

        Example:
            >>> job = await client.submit_job(
            ...     model_id="credit-score-v1",
            ...     input_data=encrypted_data,
            ...     proof_type="hybrid",
            ...     priority=2,
            ... )
            >>> print(f"Job ID: {job.id}")
        """
        self._check_closed()

        # Compute input hash
        input_hash = hashlib.sha256(input_data).hexdigest()

        request = {
            "model_id": model_id,
            "input_hash": input_hash,
            "proof_type": proof_type,
            "priority": priority,
            "timeout_seconds": timeout_seconds,
            "metadata": metadata or {},
        }

        data = await self._transport.post("/compute/jobs", request)

        return ComputeJob(
            id=data["job_id"],
            model_id=model_id,
            input_hash=input_hash,
            output_hash=None,
            status=JobStatus.PENDING,
            created_at=datetime.utcnow(),
            completed_at=None,
            block_height=None,
            seal_id=None,
            validator=None,
            proof_type=proof_type,
            metadata=metadata or {},
        )

    async def get_job(self, job_id: str) -> ComputeJob:
        """
        Get compute job status.

        Args:
            job_id: Job identifier

        Returns:
            Compute job information
        """
        self._check_closed()

        data = await self._transport.get(f"/compute/jobs/{job_id}")

        return ComputeJob(
            id=data["id"],
            model_id=data["model_id"],
            input_hash=data["input_hash"],
            output_hash=data.get("output_hash"),
            status=JobStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            completed_at=(
                datetime.fromisoformat(data["completed_at"])
                if data.get("completed_at")
                else None
            ),
            block_height=data.get("block_height"),
            seal_id=data.get("seal_id"),
            validator=data.get("validator"),
            proof_type=data["proof_type"],
            error=data.get("error"),
            metadata=data.get("metadata", {}),
        )

    async def list_jobs(
        self,
        status: Optional[JobStatus] = None,
        model_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ComputeJob]:
        """
        List compute jobs.

        Args:
            status: Filter by status
            model_id: Filter by model ID
            limit: Maximum number of results
            offset: Pagination offset

        Returns:
            List of compute jobs
        """
        self._check_closed()

        params = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status.value
        if model_id:
            params["model_id"] = model_id

        data = await self._transport.get("/compute/jobs", params=params)

        return [
            ComputeJob(
                id=j["id"],
                model_id=j["model_id"],
                input_hash=j["input_hash"],
                output_hash=j.get("output_hash"),
                status=JobStatus(j["status"]),
                created_at=datetime.fromisoformat(j["created_at"]),
                completed_at=(
                    datetime.fromisoformat(j["completed_at"])
                    if j.get("completed_at")
                    else None
                ),
                block_height=j.get("block_height"),
                seal_id=j.get("seal_id"),
                validator=j.get("validator"),
                proof_type=j["proof_type"],
                error=j.get("error"),
                metadata=j.get("metadata", {}),
            )
            for j in data.get("jobs", [])
        ]

    async def wait_for_job(
        self,
        job_id: str,
        timeout: float = 300.0,
        poll_interval: float = 2.0,
    ) -> ComputeJob:
        """
        Wait for a job to complete.

        Args:
            job_id: Job identifier
            timeout: Maximum wait time in seconds
            poll_interval: Polling interval in seconds

        Returns:
            Completed compute job

        Raises:
            TimeoutError: If job doesn't complete within timeout
            TransactionError: If job fails
        """
        self._check_closed()

        start_time = time.time()
        terminal_states = {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}

        while time.time() - start_time < timeout:
            job = await self.get_job(job_id)

            if job.status in terminal_states:
                if job.status == JobStatus.FAILED:
                    raise TransactionError(
                        f"Job {job_id} failed: {job.error}",
                        tx_error=job.error,
                    )
                return job

            await asyncio.sleep(poll_interval)

        raise TimeoutError(
            f"Job {job_id} did not complete within {timeout}s",
            operation="wait_for_job",
            timeout_seconds=timeout,
        )

    async def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending or running job.

        Args:
            job_id: Job identifier

        Returns:
            True if job was cancelled
        """
        self._check_closed()

        await self._transport.post(f"/compute/jobs/{job_id}/cancel", {})
        return True

    # -------------------------------------------------------------------------
    # Digital Seal Operations
    # -------------------------------------------------------------------------

    async def get_seal(self, seal_id: str) -> DigitalSealInfo:
        """
        Get digital seal information.

        Args:
            seal_id: Seal identifier

        Returns:
            Digital seal information
        """
        self._check_closed()

        data = await self._transport.get(f"/seals/{seal_id}")

        return DigitalSealInfo(
            id=data["id"],
            model_commitment=data["model_commitment"],
            input_commitment=data["input_commitment"],
            output_commitment=data["output_commitment"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            block_height=data["block_height"],
            validator_set=data["validator_set"],
            tee_attestations=data.get("tee_attestations", []),
            zk_proof=data.get("zk_proof"),
            regulatory_info=data.get("regulatory_info", {}),
        )

    async def wait_for_seal(
        self,
        job_id: str,
        timeout: float = 300.0,
        poll_interval: float = 2.0,
    ) -> DigitalSealInfo:
        """
        Wait for a job to complete and return its seal.

        Args:
            job_id: Job identifier
            timeout: Maximum wait time in seconds
            poll_interval: Polling interval in seconds

        Returns:
            Digital seal for the completed job

        Raises:
            TimeoutError: If seal not created within timeout
            SealNotFoundError: If job completes but no seal is created
        """
        job = await self.wait_for_job(job_id, timeout, poll_interval)

        if not job.seal_id:
            raise SealNotFoundError(
                message=f"No seal created for job {job_id}",
                seal_id=job_id,
            )

        return await self.get_seal(job.seal_id)

    async def verify_seal(self, seal_id: str) -> bool:
        """
        Verify a digital seal's integrity.

        Args:
            seal_id: Seal identifier

        Returns:
            True if seal is valid
        """
        self._check_closed()

        data = await self._transport.get(f"/seals/{seal_id}/verify")
        return data.get("valid", False)

    async def list_seals(
        self,
        model_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[DigitalSealInfo]:
        """
        List digital seals.

        Args:
            model_id: Filter by model ID
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum number of results
            offset: Pagination offset

        Returns:
            List of digital seals
        """
        self._check_closed()

        params = {"limit": limit, "offset": offset}
        if model_id:
            params["model_id"] = model_id
        if start_time:
            params["start_time"] = start_time.isoformat()
        if end_time:
            params["end_time"] = end_time.isoformat()

        data = await self._transport.get("/seals", params=params)

        return [
            DigitalSealInfo(
                id=s["id"],
                model_commitment=s["model_commitment"],
                input_commitment=s["input_commitment"],
                output_commitment=s["output_commitment"],
                timestamp=datetime.fromisoformat(s["timestamp"]),
                block_height=s["block_height"],
                validator_set=s["validator_set"],
                tee_attestations=s.get("tee_attestations", []),
                zk_proof=s.get("zk_proof"),
                regulatory_info=s.get("regulatory_info", {}),
            )
            for s in data.get("seals", [])
        ]

    async def export_audit(
        self,
        seal_id: str,
        format: str = "json",
    ) -> bytes:
        """
        Export audit report for a seal.

        Args:
            seal_id: Seal identifier
            format: Export format ("json", "pdf", "csv")

        Returns:
            Audit report data
        """
        self._check_closed()

        data = await self._transport.post(
            f"/seals/{seal_id}/audit",
            {"format": format},
        )

        # Handle base64 encoded response for binary formats
        if format in ("pdf",):
            import base64

            return base64.b64decode(data["data"])

        return json.dumps(data).encode()

    # -------------------------------------------------------------------------
    # Model Registry Operations
    # -------------------------------------------------------------------------

    async def get_model(self, model_id: str) -> ModelInfo:
        """
        Get model information from registry.

        Args:
            model_id: Model identifier

        Returns:
            Model information
        """
        self._check_closed()

        # Check cache first
        cache_key = f"model:{model_id}"
        cached = await self._cache.get(cache_key)
        if cached:
            return cached

        data = await self._transport.get(f"/models/{model_id}")

        model = ModelInfo(
            id=data["id"],
            name=data["name"],
            version=data["version"],
            hash=data["hash"],
            framework=data["framework"],
            architecture=data["architecture"],
            supported_proof_types=data.get("supported_proof_types", ["tee"]),
            min_security_level=data.get("min_security_level", 0),
            registered_at=datetime.fromisoformat(data["registered_at"]),
            owner=data["owner"],
            compliance=data.get("compliance", []),
        )

        # Cache the result
        await self._cache.set(cache_key, model)

        return model

    async def list_models(
        self,
        framework: Optional[str] = None,
        compliance: Optional[List[str]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ModelInfo]:
        """
        List registered models.

        Args:
            framework: Filter by framework
            compliance: Filter by compliance requirements
            limit: Maximum number of results
            offset: Pagination offset

        Returns:
            List of model information
        """
        self._check_closed()

        params = {"limit": limit, "offset": offset}
        if framework:
            params["framework"] = framework
        if compliance:
            params["compliance"] = ",".join(compliance)

        data = await self._transport.get("/models", params=params)

        return [
            ModelInfo(
                id=m["id"],
                name=m["name"],
                version=m["version"],
                hash=m["hash"],
                framework=m["framework"],
                architecture=m["architecture"],
                supported_proof_types=m.get("supported_proof_types", ["tee"]),
                min_security_level=m.get("min_security_level", 0),
                registered_at=datetime.fromisoformat(m["registered_at"]),
                owner=m["owner"],
                compliance=m.get("compliance", []),
            )
            for m in data.get("models", [])
        ]

    # -------------------------------------------------------------------------
    # Metrics and Health
    # -------------------------------------------------------------------------

    async def health_check(self) -> bool:
        """
        Check if the network is healthy.

        Returns:
            True if network is healthy
        """
        try:
            status = await self.get_status()
            return not status.get("syncing", True)
        except Exception:
            return False

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get client metrics.

        Returns:
            Metrics summary
        """
        return self._metrics.get_summary()

    # -------------------------------------------------------------------------
    # Streaming Operations
    # -------------------------------------------------------------------------

    async def stream_blocks(
        self,
        start_height: Optional[int] = None,
    ) -> AsyncGenerator[BlockInfo, None]:
        """
        Stream new blocks as they are produced.

        Args:
            start_height: Starting block height (current if None)

        Yields:
            Block information for each new block
        """
        self._check_closed()

        current = start_height
        if current is None:
            block = await self.get_block()
            current = block.height

        while True:
            try:
                block = await self.get_block(current)
                yield block
                current += 1
            except Exception:
                # Block not yet available, wait
                await asyncio.sleep(1.0)

    async def stream_jobs(
        self,
        model_id: Optional[str] = None,
        poll_interval: float = 5.0,
    ) -> AsyncGenerator[ComputeJob, None]:
        """
        Stream new jobs as they are created.

        Args:
            model_id: Filter by model ID
            poll_interval: Polling interval in seconds

        Yields:
            New compute jobs
        """
        self._check_closed()

        seen: set = set()

        while True:
            jobs = await self.list_jobs(model_id=model_id, limit=50)

            for job in jobs:
                if job.id not in seen:
                    seen.add(job.id)
                    yield job

            # Limit seen set size
            if len(seen) > 1000:
                seen = set(list(seen)[-500:])

            await asyncio.sleep(poll_interval)


# =============================================================================
# Sync Client Wrapper
# =============================================================================

class SyncAethelredClient:
    """
    Synchronous wrapper for AethelredClient.

    Useful for scripts and environments that don't support async.

    Example:
        >>> client = SyncAethelredClient(network=Network.TESTNET)
        >>> job = client.submit_job(
        ...     model_id="credit-score-v1",
        ...     input_data=encrypted_data,
        ... )
        >>> seal = client.wait_for_seal(job.id)
    """

    def __init__(self, *args, **kwargs):
        self._client = AethelredClient(*args, **kwargs)
        self._loop = asyncio.new_event_loop()

    def _run(self, coro: Awaitable[T]) -> T:
        """Run a coroutine synchronously."""
        return self._loop.run_until_complete(coro)

    def close(self) -> None:
        """Close the client."""
        self._run(self._client.close())
        self._loop.close()

    def __enter__(self) -> SyncAethelredClient:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # Delegate all methods
    def get_status(self) -> Dict[str, Any]:
        return self._run(self._client.get_status())

    def get_block(self, height: Optional[int] = None) -> BlockInfo:
        return self._run(self._client.get_block(height))

    def get_validators(self) -> List[ValidatorInfo]:
        return self._run(self._client.get_validators())

    def get_account(self, address: str) -> AccountInfo:
        return self._run(self._client.get_account(address))

    def submit_job(self, **kwargs) -> ComputeJob:
        return self._run(self._client.submit_job(**kwargs))

    def get_job(self, job_id: str) -> ComputeJob:
        return self._run(self._client.get_job(job_id))

    def wait_for_job(self, job_id: str, **kwargs) -> ComputeJob:
        return self._run(self._client.wait_for_job(job_id, **kwargs))

    def get_seal(self, seal_id: str) -> DigitalSealInfo:
        return self._run(self._client.get_seal(seal_id))

    def wait_for_seal(self, job_id: str, **kwargs) -> DigitalSealInfo:
        return self._run(self._client.wait_for_seal(job_id, **kwargs))

    def verify_seal(self, seal_id: str) -> bool:
        return self._run(self._client.verify_seal(seal_id))

    def get_model(self, model_id: str) -> ModelInfo:
        return self._run(self._client.get_model(model_id))

    def health_check(self) -> bool:
        return self._run(self._client.health_check())
