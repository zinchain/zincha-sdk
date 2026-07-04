import { bytesToHex, hexToBytes, normalizeAddress, signedRequestHeaders } from "./crypto.ts";
import { isMainnetRelease, parseReleaseName, releaseSpec } from "./release.ts";
import {
  createTransferTransaction,
  estimateTransferFeeMicroZin,
  signedTransactionHex,
  signTransaction,
  withValidityWindow,
} from "./transaction.ts";
import {
  createSignableTransaction,
  encodeAgentDeregisterData,
  encodeTaskAcceptData,
  encodeTaskCancelData,
  encodeTaskDisputeData,
  encodeTaskFinalizeData,
  encodeTaskFulfillData,
  encodeTaskResolveData,
  encodeAgentRegisterData,
  encodeAgentUpdateData,
  encodeTaskSubmitData,
  encodeToolDeregisterData,
  encodeToolInvokeData,
  encodeToolJobExpireData,
  encodeToolRegisterData,
  encodeToolResultAcceptData,
  encodeToolResultDisputeData,
  encodeToolResultResolveData,
  encodeToolResultSubmitData,
  encodeToolSubscriptionCancelData,
  encodeToolSubscriptionPlanCreateData,
  encodeToolSubscriptionPlanUpdateData,
  encodeToolSubscriptionRenewData,
  encodeToolSubscriptionResumeData,
  encodeToolSubscriptionStartData,
  encodeToolSubscriptionTopUpData,
  encodeToolUpdateData,
  encodeToolUsageAcceptData,
  encodeToolUsageDisputeData,
  encodeToolUsageExpireData,
  encodeToolUsageReportData,
  encodeToolUsageResolveData,
  encodeTokenApproveData,
  encodeTokenBurnData,
  encodeTokenCreateData,
  encodeTokenMintData,
  encodeTokenTransferData,
  encodeStakeData,
  encodeUnstakeData,
  encodeValidatorExitData,
  encodeValidatorRegisterData,
  encodeValidatorUpdateData,
  encodeValidatorVrfCommitData,
  encodeValidatorVrfContributionData,
  encodeContractCallData,
  encodeContractDeactivateData,
  encodeContractDeployData,
  encodeContractPublishAbiData,
  encodeContractRouteCallData,
  encodeContractRouteUpdateData,
  encodeContractVerifyData,
  type AgentDeregisterInput,
  type AgentUpdateInput,
  type ContractCallInput,
  type ContractDeactivateInput,
  type ContractDeployInput,
  type ContractPublishAbiInput,
  type ContractRouteCallInput,
  type ContractRouteUpdateInput,
  type ContractVerifyInput,
  type TaskAcceptInput,
  type TaskCancelInput,
  type TaskDisputeInput,
  type TaskFinalizeInput,
  type TaskFulfillInput,
  type TaskResolveInput,
  type ToolDeregisterInput,
  type ToolInvokeInput,
  type ToolJobExpireInput,
  type ToolRegisterInput,
  type ToolResultAcceptInput,
  type ToolResultDisputeInput,
  type ToolResultResolveInput,
  type ToolResultSubmitInput,
  type ToolSubscriptionCancelInput,
  type ToolSubscriptionPlanCreateInput,
  type ToolSubscriptionPlanUpdateInput,
  type ToolSubscriptionRenewInput,
  type ToolSubscriptionResumeInput,
  type ToolSubscriptionStartInput,
  type ToolSubscriptionTopUpInput,
  type ToolUpdateInput,
  type ToolUsageAcceptInput,
  type ToolUsageDisputeInput,
  type ToolUsageExpireInput,
  type ToolUsageReportInput,
  type ToolUsageResolveInput,
  type RegisterAgentInput,
  type SubmitTaskInput,
  type TokenApproveInput,
  type TokenBurnInput,
  type TokenCreateInput,
  type TokenMintInput,
  type TokenTransferInput,
  type StakeInput,
  type UnstakeInput,
  type ValidatorExitInput,
  type ValidatorRegisterInput,
  type ValidatorUpdateInput,
  type ValidatorVrfCommitInput,
  type ValidatorVrfContributionInput,
} from "./builders.ts";
import type {
  ApiResponse,
  BalanceResponse,
  BigNumberish,
  ChainInfo,
  FaucetRequest,
  FaucetResponse,
  Hex,
  NonceResponse,
  ReleaseName,
  RequestOptions,
  SignedTransaction,
  SubmitTransactionResponse,
  TransactionStatus,
  TransactionHistoryQuery,
  TransferInput,
  TxTypeName,
  ZinchaClientOptions,
} from "./types.ts";
import { Keypair } from "./crypto.ts";

export class ZinchaApiError extends Error {
  readonly status: number;
  readonly data: unknown;

  constructor(status: number, message: string, data?: unknown) {
    super(message);
    this.name = "ZinchaApiError";
    this.status = status;
    this.data = data;
  }
}

export class ZinchaClient {
  readonly baseUrl: string;
  readonly faucetUrl: string;
  readonly websocketUrl?: string;
  readonly release?: ReleaseName;
  private readonly bearerToken?: string;
  private readonly signer?: ZinchaClientOptions["signer"];
  private readonly fetchImpl: typeof fetch;

  constructor(options: ZinchaClientOptions = {}) {
    const release = options.release ? parseReleaseName(options.release) : undefined;
    const spec = release ? releaseSpec(release) : undefined;
    this.release = release;
    this.baseUrl = trimTrailingSlash(options.baseUrl ?? spec?.canonicalRpcUrl ?? "http://127.0.0.1:9944");
    this.faucetUrl = trimTrailingSlash(options.faucetUrl ?? (options.baseUrl ? this.baseUrl : spec?.faucetUrl) ?? this.baseUrl);
    this.websocketUrl = options.websocketUrl ?? spec?.canonicalWebsocketUrl;
    this.bearerToken = options.bearerToken;
    this.signer = options.signer;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    if (!this.fetchImpl) {
      throw new Error("ZinchaClient requires a fetch implementation");
    }
  }

  static forRelease(release: ReleaseName | string, options: Omit<ZinchaClientOptions, "release"> = {}): ZinchaClient {
    return new ZinchaClient({ ...options, release });
  }

  async request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
    return this.requestFromBase<T>(this.baseUrl, method, path, options);
  }

  private async requestFromBase<T>(
    baseUrl: string,
    method: string,
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    const requestTarget = buildRequestTarget(path, options.query);
    const url = `${baseUrl}${requestTarget}`;
    const body = options.body === undefined ? undefined : JSON.stringify(options.body);
    const headers: Record<string, string> = {
      accept: "application/json",
    };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }
    const bearer = options.bearerToken ?? this.bearerToken;
    if (bearer) {
      headers.authorization = `Bearer ${bearer}`;
    }
    if (options.signed) {
      if (!this.signer) {
        throw new Error("signed request requires a client signer");
      }
      Object.assign(headers, signedRequestHeaders(this.signer, {
        method,
        requestTarget,
        body: body ?? "",
      }));
    }

    const response = await this.fetchImpl(url, {
      method,
      headers,
      body,
      signal: options.signal,
    });
    const text = await response.text();
    let parsed: ApiResponse<T> | unknown;
    try {
      parsed = text.length === 0 ? null : JSON.parse(text);
    } catch (error) {
      throw new ZinchaApiError(response.status, `invalid JSON response: ${String(error)}`, text);
    }
    if (!response.ok) {
      const api = parsed as Partial<ApiResponse<unknown>> | null;
      throw new ZinchaApiError(response.status, api?.error ?? response.statusText, api?.data);
    }
    const api = parsed as ApiResponse<T>;
    if (!api || api.success !== true) {
      throw new ZinchaApiError(response.status, api?.error ?? "ZINCHA API request failed", api?.data);
    }
    return api.data as T;
  }

  get<T>(path: string, options: Omit<RequestOptions, "body"> = {}): Promise<T> {
    return this.request<T>("GET", path, options);
  }

  post<T>(path: string, body?: unknown, options: Omit<RequestOptions, "body"> = {}): Promise<T> {
    return this.request<T>("POST", path, { ...options, body });
  }

  chainInfo(): Promise<ChainInfo> {
    return this.get<ChainInfo>("/v1/chain/info");
  }

  chainStats(): Promise<unknown> {
    return this.get("/v1/chain/stats");
  }

  latestBlock(): Promise<unknown> {
    return this.get("/v1/blocks/latest");
  }

  blockByNumber(number: number): Promise<unknown> {
    return this.get(`/v1/blocks/${number}`);
  }

  balance(address: string): Promise<BalanceResponse> {
    return this.get<BalanceResponse>(`/v1/accounts/${normalizeAddress(address)}/balance`);
  }

  nonce(address: string): Promise<NonceResponse> {
    return this.get<NonceResponse>(`/v1/accounts/${normalizeAddress(address)}/nonce`);
  }

  accountTransactions(address: string, query?: TransactionHistoryQuery): Promise<unknown> {
    return this.get(`/v1/accounts/${normalizeAddress(address)}/transactions`, {
      query: transactionHistoryQuery(query),
    });
  }

  transaction(hash: Hex): Promise<TransactionStatus> {
    return this.get<TransactionStatus>(`/v1/tx/${normalizeHash(hash)}`);
  }

  submitTransactionHex(signedTxHex: Hex): Promise<SubmitTransactionResponse> {
    return this.post<SubmitTransactionResponse>("/v1/tx/submit", {
      signed_tx_hex: normalizeHexEven(signedTxHex),
    });
  }

  submitSignedTransaction(tx: SignedTransaction): Promise<SubmitTransactionResponse> {
    return this.submitTransactionHex(signedTransactionHex(tx));
  }

  submitTransactionBatch(signedTxHexes: Hex[]): Promise<unknown> {
    return this.post("/v1/tx/submit/batch", {
      signed_transactions_hex: signedTxHexes.map(normalizeHexEven),
    });
  }

  async buildTransfer(keypair: Keypair, input: TransferInput): Promise<SignedTransaction> {
    const validityFields = [
      input.referenceBlockHeight,
      input.referenceBlockHash,
      input.maxValidBlockHeight,
    ].filter((value) => value !== undefined).length;
    if (validityFields > 0 && validityFields < 3) {
      throw new Error("referenceBlockHeight, referenceBlockHash, and maxValidBlockHeight must be provided together");
    }
    const needsValidityWindow = validityFields === 0;
    const needsChainInfo =
      input.chainId === undefined
      || input.feeMicroZin === undefined
      || needsValidityWindow;
    const chainInfo = needsChainInfo ? await this.chainInfo() : undefined;
    const nonce = input.nonce ?? (await this.nonce(keypair.address())).next_nonce;
    const chainId = input.chainId ?? chainInfo?.chain_id;
    if (!chainId) {
      throw new Error("chainId is required when chain info is not available");
    }
    const fee = input.feeMicroZin ?? estimateTransferFeeMicroZin(chainInfo?.next_base_fee ?? 0);
    let tx = createTransferTransaction(keypair, {
      ...input,
      chainId,
      nonce,
      feeMicroZin: fee,
    });
    const ttl = chainInfo?.transaction_ttl_blocks;
    if (
      input.referenceBlockHeight === undefined
      && input.referenceBlockHash === undefined
      && input.maxValidBlockHeight === undefined
      && chainInfo
      && ttl !== undefined
    ) {
      tx = withValidityWindow(
        tx,
        chainInfo.transaction_reference_block_height,
        chainInfo.transaction_reference_block_hash,
        ttl,
      );
    }
    return signTransaction(tx, keypair);
  }

  async transferAndSubmit(keypair: Keypair, input: TransferInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildTransfer(keypair, input));
  }

  /**
   * Build, sign, and return an `agent_register` transaction. Auto-fetches
   * `chain_id` and `nonce` from the node when omitted, and pins the
   * transaction's validity window to the chain's current reference block.
   */
  async buildRegisterAgent(keypair: Keypair, input: RegisterAgentInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "agent_register", input, encodeAgentRegisterData(input));
  }

  /** Convenience: build + submit an `agent_register` transaction. */
  async registerAgentAndSubmit(keypair: Keypair, input: RegisterAgentInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildRegisterAgent(keypair, input));
  }

  /** Build, sign, and return an `agent_update` transaction. */
  async buildUpdateAgent(keypair: Keypair, input: AgentUpdateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "agent_update", input, encodeAgentUpdateData(input));
  }

  /** Convenience: build + submit an `agent_update` transaction. */
  async updateAgentAndSubmit(keypair: Keypair, input: AgentUpdateInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateAgent(keypair, input));
  }

  /** Build, sign, and return an `agent_deregister` transaction. */
  async buildDeregisterAgent(keypair: Keypair, input: AgentDeregisterInput = {}): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "agent_deregister", input, encodeAgentDeregisterData(input));
  }

  /** Convenience: build + submit an `agent_deregister` transaction. */
  async deregisterAgentAndSubmit(
    keypair: Keypair,
    input: AgentDeregisterInput = {},
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDeregisterAgent(keypair, input));
  }

  /**
   * Build, sign, and return a `task_submit` transaction. Auto-fetches
   * `chain_id` and `nonce` from the node when omitted, and pins the
   * transaction's validity window to the chain's current reference block.
   */
  async buildSubmitTask(keypair: Keypair, input: SubmitTaskInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "task_submit", input, encodeTaskSubmitData(input));
  }

  /** Convenience: build + submit a `task_submit` transaction. */
  async submitTaskAndSubmit(keypair: Keypair, input: SubmitTaskInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildSubmitTask(keypair, input));
  }

  /** Build, sign, and return a `task_fulfill` transaction. */
  async buildFulfillTask(keypair: Keypair, input: TaskFulfillInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "task_fulfill", input, encodeTaskFulfillData(input));
  }

  /** Convenience: build + submit a `task_fulfill` transaction. */
  async fulfillTaskAndSubmit(keypair: Keypair, input: TaskFulfillInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildFulfillTask(keypair, input));
  }

  /** Build, sign, and return a `task_accept` transaction. */
  async buildAcceptTask(keypair: Keypair, input: TaskAcceptInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "task_accept", input, encodeTaskAcceptData(input));
  }

  /** Convenience: build + submit a `task_accept` transaction. */
  async acceptTaskAndSubmit(keypair: Keypair, input: TaskAcceptInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildAcceptTask(keypair, input));
  }

  /** Build, sign, and return a `task_dispute` transaction. */
  async buildDisputeTask(keypair: Keypair, input: TaskDisputeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "task_dispute", input, encodeTaskDisputeData(input));
  }

  /** Convenience: build + submit a `task_dispute` transaction. */
  async disputeTaskAndSubmit(keypair: Keypair, input: TaskDisputeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDisputeTask(keypair, input));
  }

  /** Build, sign, and return a `task_resolve` transaction. */
  async buildResolveTask(keypair: Keypair, input: TaskResolveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "task_resolve", input, encodeTaskResolveData(input));
  }

  /** Convenience: build + submit a `task_resolve` transaction. */
  async resolveTaskAndSubmit(keypair: Keypair, input: TaskResolveInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildResolveTask(keypair, input));
  }

  /** Build, sign, and return a `task_finalize` transaction. */
  async buildFinalizeTask(keypair: Keypair, input: TaskFinalizeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "task_finalize", input, encodeTaskFinalizeData(input));
  }

  /** Convenience: build + submit a `task_finalize` transaction. */
  async finalizeTaskAndSubmit(keypair: Keypair, input: TaskFinalizeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildFinalizeTask(keypair, input));
  }

  /** Build, sign, and return a `task_cancel` transaction. */
  async buildCancelTask(keypair: Keypair, input: TaskCancelInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "task_cancel", input, encodeTaskCancelData(input));
  }

  /** Convenience: build + submit a `task_cancel` transaction. */
  async cancelTaskAndSubmit(keypair: Keypair, input: TaskCancelInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCancelTask(keypair, input));
  }

  /** Build, sign, and return a `token_create` transaction. */
  async buildCreateToken(keypair: Keypair, input: TokenCreateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "token_create", input, encodeTokenCreateData(input));
  }

  /** Convenience: build + submit a `token_create` transaction. */
  async createTokenAndSubmit(keypair: Keypair, input: TokenCreateInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCreateToken(keypair, input));
  }

  /** Build, sign, and return a `token_transfer` transaction. */
  async buildTransferToken(keypair: Keypair, input: TokenTransferInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "token_transfer", input, encodeTokenTransferData(input));
  }

  /** Convenience: build + submit a `token_transfer` transaction. */
  async transferTokenAndSubmit(keypair: Keypair, input: TokenTransferInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildTransferToken(keypair, input));
  }

  /** Build, sign, and return a `token_approve` transaction. */
  async buildApproveToken(keypair: Keypair, input: TokenApproveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "token_approve", input, encodeTokenApproveData(input));
  }

  /** Convenience: build + submit a `token_approve` transaction. */
  async approveTokenAndSubmit(keypair: Keypair, input: TokenApproveInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildApproveToken(keypair, input));
  }

  /** Build, sign, and return a `token_mint` transaction. */
  async buildMintToken(keypair: Keypair, input: TokenMintInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "token_mint", input, encodeTokenMintData(input));
  }

  /** Convenience: build + submit a `token_mint` transaction. */
  async mintTokenAndSubmit(keypair: Keypair, input: TokenMintInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildMintToken(keypair, input));
  }

  /** Build, sign, and return a `token_burn` transaction. */
  async buildBurnToken(keypair: Keypair, input: TokenBurnInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "token_burn", input, encodeTokenBurnData(input));
  }

  /** Convenience: build + submit a `token_burn` transaction. */
  async burnTokenAndSubmit(keypair: Keypair, input: TokenBurnInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildBurnToken(keypair, input));
  }

  /** Build, sign, and return a `tool_register` transaction. */
  async buildRegisterTool(keypair: Keypair, input: ToolRegisterInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_register", input, encodeToolRegisterData(input));
  }

  /** Convenience: build + submit a `tool_register` transaction. */
  async registerToolAndSubmit(keypair: Keypair, input: ToolRegisterInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildRegisterTool(keypair, input));
  }

  /** Build, sign, and return a `tool_update` transaction. */
  async buildUpdateTool(keypair: Keypair, input: ToolUpdateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_update", input, encodeToolUpdateData(input));
  }

  /** Convenience: build + submit a `tool_update` transaction. */
  async updateToolAndSubmit(keypair: Keypair, input: ToolUpdateInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateTool(keypair, input));
  }

  /** Build, sign, and return a `tool_invoke` transaction. */
  async buildInvokeTool(keypair: Keypair, input: ToolInvokeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_invoke", input, encodeToolInvokeData(input));
  }

  /** Convenience: build + submit a `tool_invoke` transaction. */
  async invokeToolAndSubmit(keypair: Keypair, input: ToolInvokeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildInvokeTool(keypair, input));
  }

  /** Build, sign, and return a `tool_deregister` transaction. */
  async buildDeregisterTool(keypair: Keypair, input: ToolDeregisterInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_deregister", input, encodeToolDeregisterData(input));
  }

  /** Convenience: build + submit a `tool_deregister` transaction. */
  async deregisterToolAndSubmit(keypair: Keypair, input: ToolDeregisterInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDeregisterTool(keypair, input));
  }

  async buildSubmitToolResult(keypair: Keypair, input: ToolResultSubmitInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_result_submit", input, encodeToolResultSubmitData(input));
  }

  async submitToolResultAndSubmit(keypair: Keypair, input: ToolResultSubmitInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildSubmitToolResult(keypair, input));
  }

  async buildAcceptToolResult(keypair: Keypair, input: ToolResultAcceptInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_result_accept", input, encodeToolResultAcceptData(input));
  }

  async acceptToolResultAndSubmit(keypair: Keypair, input: ToolResultAcceptInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildAcceptToolResult(keypair, input));
  }

  async buildDisputeToolResult(keypair: Keypair, input: ToolResultDisputeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_result_dispute", input, encodeToolResultDisputeData(input));
  }

  async disputeToolResultAndSubmit(keypair: Keypair, input: ToolResultDisputeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDisputeToolResult(keypair, input));
  }

  async buildResolveToolResult(keypair: Keypair, input: ToolResultResolveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_result_resolve", input, encodeToolResultResolveData(input));
  }

  async resolveToolResultAndSubmit(keypair: Keypair, input: ToolResultResolveInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildResolveToolResult(keypair, input));
  }

  async buildExpireToolJob(keypair: Keypair, input: ToolJobExpireInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_job_expire", input, encodeToolJobExpireData(input));
  }

  async expireToolJobAndSubmit(keypair: Keypair, input: ToolJobExpireInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildExpireToolJob(keypair, input));
  }

  async buildReportToolUsage(keypair: Keypair, input: ToolUsageReportInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_usage_report", input, encodeToolUsageReportData(input));
  }

  async reportToolUsageAndSubmit(keypair: Keypair, input: ToolUsageReportInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildReportToolUsage(keypair, input));
  }

  async buildAcceptToolUsage(keypair: Keypair, input: ToolUsageAcceptInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_usage_accept", input, encodeToolUsageAcceptData(input));
  }

  async acceptToolUsageAndSubmit(keypair: Keypair, input: ToolUsageAcceptInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildAcceptToolUsage(keypair, input));
  }

  async buildDisputeToolUsage(keypair: Keypair, input: ToolUsageDisputeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_usage_dispute", input, encodeToolUsageDisputeData(input));
  }

  async disputeToolUsageAndSubmit(keypair: Keypair, input: ToolUsageDisputeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDisputeToolUsage(keypair, input));
  }

  async buildResolveToolUsage(keypair: Keypair, input: ToolUsageResolveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_usage_resolve", input, encodeToolUsageResolveData(input));
  }

  async resolveToolUsageAndSubmit(keypair: Keypair, input: ToolUsageResolveInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildResolveToolUsage(keypair, input));
  }

  async buildExpireToolUsage(keypair: Keypair, input: ToolUsageExpireInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_usage_expire", input, encodeToolUsageExpireData(input));
  }

  async expireToolUsageAndSubmit(keypair: Keypair, input: ToolUsageExpireInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildExpireToolUsage(keypair, input));
  }

  async buildCreateToolSubscriptionPlan(
    keypair: Keypair,
    input: ToolSubscriptionPlanCreateInput,
  ): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "tool_subscription_plan_create",
      input,
      encodeToolSubscriptionPlanCreateData(input),
    );
  }

  async createToolSubscriptionPlanAndSubmit(
    keypair: Keypair,
    input: ToolSubscriptionPlanCreateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCreateToolSubscriptionPlan(keypair, input));
  }

  async buildUpdateToolSubscriptionPlan(
    keypair: Keypair,
    input: ToolSubscriptionPlanUpdateInput,
  ): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "tool_subscription_plan_update",
      input,
      encodeToolSubscriptionPlanUpdateData(input),
    );
  }

  async updateToolSubscriptionPlanAndSubmit(
    keypair: Keypair,
    input: ToolSubscriptionPlanUpdateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateToolSubscriptionPlan(keypair, input));
  }

  async buildStartToolSubscription(keypair: Keypair, input: ToolSubscriptionStartInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_subscription_start", input, encodeToolSubscriptionStartData(input));
  }

  async startToolSubscriptionAndSubmit(
    keypair: Keypair,
    input: ToolSubscriptionStartInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildStartToolSubscription(keypair, input));
  }

  async buildTopUpToolSubscription(keypair: Keypair, input: ToolSubscriptionTopUpInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_subscription_top_up", input, encodeToolSubscriptionTopUpData(input));
  }

  async topUpToolSubscriptionAndSubmit(
    keypair: Keypair,
    input: ToolSubscriptionTopUpInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildTopUpToolSubscription(keypair, input));
  }

  async buildCancelToolSubscription(keypair: Keypair, input: ToolSubscriptionCancelInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_subscription_cancel", input, encodeToolSubscriptionCancelData(input));
  }

  async cancelToolSubscriptionAndSubmit(
    keypair: Keypair,
    input: ToolSubscriptionCancelInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCancelToolSubscription(keypair, input));
  }

  async buildResumeToolSubscription(keypair: Keypair, input: ToolSubscriptionResumeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_subscription_resume", input, encodeToolSubscriptionResumeData(input));
  }

  async resumeToolSubscriptionAndSubmit(
    keypair: Keypair,
    input: ToolSubscriptionResumeInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildResumeToolSubscription(keypair, input));
  }

  async buildRenewToolSubscription(keypair: Keypair, input: ToolSubscriptionRenewInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(keypair, "tool_subscription_renew", input, encodeToolSubscriptionRenewData(input));
  }

  async renewToolSubscriptionAndSubmit(
    keypair: Keypair,
    input: ToolSubscriptionRenewInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildRenewToolSubscription(keypair, input));
  }

  async buildDeployContract(keypair: Keypair, input: ContractDeployInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "contract_deploy",
      input,
      encodeContractDeployData(input),
    );
  }

  async deployContractAndSubmit(
    keypair: Keypair,
    input: ContractDeployInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDeployContract(keypair, input));
  }

  async buildCallContract(keypair: Keypair, input: ContractCallInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "contract_call",
      input,
      encodeContractCallData(input),
    );
  }

  async callContractAndSubmit(
    keypair: Keypair,
    input: ContractCallInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCallContract(keypair, input));
  }

  async buildVerifyContract(keypair: Keypair, input: ContractVerifyInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "contract_verify",
      input,
      encodeContractVerifyData(input),
    );
  }

  async verifyContractAndSubmit(
    keypair: Keypair,
    input: ContractVerifyInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildVerifyContract(keypair, input));
  }

  async buildPublishContractAbi(keypair: Keypair, input: ContractPublishAbiInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "contract_publish_abi",
      input,
      encodeContractPublishAbiData(input),
    );
  }

  async publishContractAbiAndSubmit(
    keypair: Keypair,
    input: ContractPublishAbiInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildPublishContractAbi(keypair, input));
  }

  async buildUpdateContractRoute(keypair: Keypair, input: ContractRouteUpdateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "contract_route_update",
      input,
      encodeContractRouteUpdateData(input),
    );
  }

  async updateContractRouteAndSubmit(
    keypair: Keypair,
    input: ContractRouteUpdateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateContractRoute(keypair, input));
  }

  async buildCallContractRoute(keypair: Keypair, input: ContractRouteCallInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "contract_route_call",
      input,
      encodeContractRouteCallData(input),
    );
  }

  async callContractRouteAndSubmit(
    keypair: Keypair,
    input: ContractRouteCallInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCallContractRoute(keypair, input));
  }

  async buildDeactivateContract(keypair: Keypair, input: ContractDeactivateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "contract_deactivate",
      input,
      encodeContractDeactivateData(input),
    );
  }

  async deactivateContractAndSubmit(
    keypair: Keypair,
    input: ContractDeactivateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDeactivateContract(keypair, input));
  }

  async buildRegisterValidator(keypair: Keypair, input: ValidatorRegisterInput): Promise<SignedTransaction> {
    const vrfPublicKey = input.vrfPublicKey ?? keypair.publicKeyHex();
    return this.buildTypedTransaction(
      keypair,
      "validator_register",
      { ...input, amountMicroZin: input.stakeMicroZin },
      encodeValidatorRegisterData({ ...input, vrfPublicKey }),
    );
  }

  async registerValidatorAndSubmit(
    keypair: Keypair,
    input: ValidatorRegisterInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildRegisterValidator(keypair, input));
  }

  async buildUpdateValidator(keypair: Keypair, input: ValidatorUpdateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "validator_update",
      input,
      encodeValidatorUpdateData(input),
    );
  }

  async updateValidatorAndSubmit(
    keypair: Keypair,
    input: ValidatorUpdateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateValidator(keypair, input));
  }

  async buildExitValidator(keypair: Keypair, input: ValidatorExitInput = {}): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "validator_exit",
      input,
      encodeValidatorExitData(input),
    );
  }

  async exitValidatorAndSubmit(
    keypair: Keypair,
    input: ValidatorExitInput = {},
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildExitValidator(keypair, input));
  }

  async buildCommitValidatorVrf(
    keypair: Keypair,
    input: ValidatorVrfCommitInput,
  ): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "validator_vrf_commit",
      input,
      encodeValidatorVrfCommitData(input),
    );
  }

  async commitValidatorVrfAndSubmit(
    keypair: Keypair,
    input: ValidatorVrfCommitInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCommitValidatorVrf(keypair, input));
  }

  async buildContributeValidatorVrf(
    keypair: Keypair,
    input: ValidatorVrfContributionInput,
  ): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "validator_vrf_contribution",
      input,
      encodeValidatorVrfContributionData(input),
    );
  }

  async contributeValidatorVrfAndSubmit(
    keypair: Keypair,
    input: ValidatorVrfContributionInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildContributeValidatorVrf(keypair, input));
  }

  async buildStake(keypair: Keypair, input: StakeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      keypair,
      "stake",
      { ...input, amountMicroZin: input.amountMicroZin },
      encodeStakeData(input),
    );
  }

  async stakeAndSubmit(keypair: Keypair, input: StakeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildStake(keypair, input));
  }

  async buildUnstake(keypair: Keypair, input: UnstakeInput): Promise<SignedTransaction> {
    if (input.target === "requester_auto_match") {
      throw new Error("requester_auto_match stake cannot be unstaked");
    }
    return this.buildTypedTransaction(
      keypair,
      "unstake",
      { ...input, amountMicroZin: input.amountMicroZin },
      encodeUnstakeData(input),
    );
  }

  async unstakeAndSubmit(keypair: Keypair, input: UnstakeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUnstake(keypair, input));
  }

  /**
   * Internal helper: assemble + sign a typed transaction. Mirrors the
   * chain-aware behavior of `buildTransfer` for any tx type whose data
   * payload has already been bincode-encoded.
   */
  private async buildTypedTransaction(
    keypair: Keypair,
    txType: TxTypeName,
    input: {
      nonce?: BigNumberish;
      feeMicroZin?: BigNumberish;
      maxPriorityFeePerGas?: BigNumberish;
      chainId?: string;
      timestampMs?: BigNumberish;
      referenceBlockHeight?: BigNumberish;
      referenceBlockHash?: Hex;
      maxValidBlockHeight?: BigNumberish;
      amountMicroZin?: BigNumberish;
    },
    data: Uint8Array,
  ): Promise<SignedTransaction> {
    const validityFields = [
      input.referenceBlockHeight,
      input.referenceBlockHash,
      input.maxValidBlockHeight,
    ].filter((value) => value !== undefined).length;
    if (validityFields > 0 && validityFields < 3) {
      throw new Error("referenceBlockHeight, referenceBlockHash, and maxValidBlockHeight must be provided together");
    }
    const needsValidityWindow = validityFields === 0;
    const needsChainInfo = input.chainId === undefined || needsValidityWindow;
    const chainInfo = needsChainInfo ? await this.chainInfo() : undefined;
    const chainId = input.chainId ?? chainInfo?.chain_id;
    if (!chainId) {
      throw new Error("chainId is required when chain info is not available");
    }
    const nonce = input.nonce ?? (await this.nonce(keypair.address())).next_nonce;

    let tx = createSignableTransaction({
      txType,
      sender: keypair.address(),
      data,
      nonce,
      chainId,
      amountMicroZin: input.amountMicroZin ?? 0n,
      feeMicroZin: input.feeMicroZin ?? 0n,
      maxPriorityFeePerGas: input.maxPriorityFeePerGas ?? 0n,
      timestampMs: input.timestampMs,
      referenceBlockHeight: input.referenceBlockHeight,
      referenceBlockHash: input.referenceBlockHash,
      maxValidBlockHeight: input.maxValidBlockHeight,
    });

    if (needsValidityWindow && chainInfo && chainInfo.transaction_ttl_blocks !== undefined) {
      tx = withValidityWindow(
        tx,
        chainInfo.transaction_reference_block_height,
        chainInfo.transaction_reference_block_hash,
        chainInfo.transaction_ttl_blocks,
      );
    }

    return signTransaction(tx, keypair);
  }

  requestFaucet(request: FaucetRequest): Promise<FaucetResponse> {
    if (this.release && isMainnetRelease(this.release)) {
      throw new Error("faucet is unavailable for mainnet releases");
    }
    return this.requestFromBase<FaucetResponse>(this.faucetUrl, "POST", "/v1/faucet", {
      body: {
        ...request,
        address: normalizeAddress(request.address),
      },
    });
  }

  agents(query?: Record<string, string | number | boolean | undefined>): Promise<unknown> {
    return this.get("/v1/agents", { query });
  }

  agent(address: string): Promise<unknown> {
    return this.get(`/v1/agents/${normalizeAddress(address)}`);
  }

  pendingTasks(query?: Record<string, string | number | boolean | undefined>): Promise<unknown> {
    return this.get("/v1/tasks/pending", { query });
  }

  taskOpportunity(id: Hex): Promise<unknown> {
    return this.get(`/v1/tasks/${normalizeHash(id)}/opportunity`);
  }

  task(id: Hex, options: Omit<RequestOptions, "body" | "query" | "signed"> = {}): Promise<unknown> {
    return this.get(`/v1/tasks/${normalizeHash(id)}`, { ...options, signed: true });
  }

  tools(query?: Record<string, string | number | boolean | undefined>): Promise<unknown> {
    return this.get("/v1/tools", { query });
  }

  contracts(query?: Record<string, string | number | boolean | undefined>): Promise<unknown> {
    return this.get("/v1/contracts", { query });
  }

  contract(address: string): Promise<unknown> {
    return this.get(`/v1/contracts/${normalizeAddress(address)}`);
  }

  contractTransactions(address: string, query?: TransactionHistoryQuery): Promise<unknown> {
    return this.get(`/v1/contracts/${normalizeAddress(address)}/transactions`, {
      query: transactionHistoryQuery(query),
    });
  }

  contractCapabilities(): Promise<unknown> {
    return this.get("/v1/contracts/capabilities");
  }

  tokens(query?: Record<string, string | number | boolean | undefined>): Promise<unknown> {
    return this.get("/v1/tokens", { query });
  }

  token(id: Hex): Promise<unknown> {
    return this.get(`/v1/tokens/${normalizeHash(id)}`);
  }

  tokenTransactions(id: Hex, query?: TransactionHistoryQuery): Promise<unknown> {
    return this.get(`/v1/tokens/${normalizeHash(id)}/transactions`, {
      query: transactionHistoryQuery(query),
    });
  }

  validators(): Promise<unknown> {
    return this.get("/v1/consensus/validators");
  }

  finalityStats(): Promise<unknown> {
    return this.get("/v1/finality/stats");
  }

  networkSummary(): Promise<unknown> {
    return this.get("/v1/network/summary");
  }

  pipelineStatus(): Promise<unknown> {
    return this.get("/v1/pipeline/status");
  }

  events(query?: Record<string, string | number | boolean | undefined>): Promise<unknown> {
    return this.get("/v1/events", { query });
  }

  openWebSocket(path = "/ws"): WebSocket {
    const WebSocketCtor = globalThis.WebSocket;
    if (!WebSocketCtor) {
      throw new Error("global WebSocket is unavailable in this runtime");
    }
    const base = this.websocketUrl ?? httpToWebsocketUrl(this.baseUrl);
    return new WebSocketCtor(`${trimTrailingSlash(base)}${path}`);
  }

  signedRequestHeaders(method: string, path: string, body?: unknown): Record<string, string> {
    if (!this.signer) {
      throw new Error("signed request requires a client signer");
    }
    const payload = body === undefined ? "" : JSON.stringify(body);
    return signedRequestHeaders(this.signer, {
      method,
      requestTarget: path,
      body: payload,
    });
  }
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function buildRequestTarget(path: string, query?: RequestOptions["query"]): string {
  const target = path.startsWith("/") ? path : `/${path}`;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null) {
      params.set(key, String(value));
    }
  }
  const encoded = params.toString();
  return encoded ? `${target}?${encoded}` : target;
}

function transactionHistoryQuery(query?: TransactionHistoryQuery): RequestOptions["query"] {
  return {
    limit: query?.limit,
    cursor: query?.cursor,
  };
}

function httpToWebsocketUrl(baseUrl: string): string {
  if (baseUrl.startsWith("https://")) {
    return `wss://${baseUrl.slice("https://".length)}`;
  }
  if (baseUrl.startsWith("http://")) {
    return `ws://${baseUrl.slice("http://".length)}`;
  }
  throw new Error(`cannot derive websocket URL from ${baseUrl}`);
}

function normalizeHash(hash: Hex): Hex {
  const bytes = hexToBytes(hash, 32);
  return bytesToHex(bytes);
}

function normalizeHexEven(hex: Hex): Hex {
  const normalized = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(normalized)) {
    throw new Error("invalid hex string");
  }
  return normalized.toLowerCase();
}
