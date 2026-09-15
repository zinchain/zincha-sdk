import { bytesToHex, hexToBytes, normalizeAddress, signedRequestHeadersAsync } from "./crypto.ts";
import { isMainnetRelease, parseReleaseName, releaseSpec } from "./release.ts";
import {
  createTransferTransaction,
  estimateTransferFeeMicroZin,
  signedTransactionHex,
  signTransactionWith,
  withValidityWindow,
} from "./transaction.ts";
import {
  createSignableTransaction,
  encodeAgreementAcceptData,
  encodeAgreementCancelData,
  encodeAgreementCreateData,
  encodeAgreementDisputeData,
  encodeAgreementExecuteData,
  encodeAgreementResolveData,
  encodeAgentDeregisterData,
  encodeTaskAcceptData,
  encodeTaskCancelData,
  encodeTaskDisputeData,
  encodeTaskFinalizeData,
  encodeTaskFulfillData,
  encodeReputationUpdateData,
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
  encodeCapabilityApproveData,
  encodeCapabilityDeprecateData,
  encodeCapabilityProposeData,
  encodeCapabilityRejectData,
  type AgentDeregisterInput,
  type AgentUpdateInput,
  type AgreementAcceptInput,
  type AgreementCancelInput,
  type AgreementCreateInput,
  type AgreementDisputeInput,
  type AgreementExecuteInput,
  type AgreementResolveInput,
  type CapabilityApproveInput,
  type CapabilityDeprecateInput,
  type CapabilityProposeInput,
  type CapabilityRejectInput,
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
  type ReputationUpdateInput,
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
  CapabilityListQuery,
  CapabilitySearchQuery,
  ChainInfo,
  CursorPageQuery,
  EmbedOptions,
  FaucetRequest,
  FaucetResponse,
  Hex,
  MarketRateListResponse,
  NonceResponse,
  ParticipantWorkflowQuery,
  PendingTaskListQuery,
  ReleaseName,
  RequestOptions,
  SignedTransaction,
  SubmitBatchResult,
  SubmitTransactionResponse,
  TransactionStatus,
  TransactionHistoryQuery,
  TransferInput,
  TxTypeName,
  ZinchaClientOptions,
} from "./types.ts";
import type { TransactionSigner } from "./types.ts";

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
  readonly embedUrl?: string;
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
    this.embedUrl = optionalTrimTrailingSlash(options.embedUrl ?? embedUrlFromEnv());
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
      Object.assign(headers, await signedRequestHeadersAsync(this.signer, {
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

  capabilities(query?: CapabilityListQuery): Promise<unknown> {
    return this.get("/v1/capabilities", {
      query: capabilityListQuery(query),
    });
  }

  capabilitySearch(q: string, query?: CapabilitySearchQuery): Promise<unknown> {
    return this.get("/v1/capabilities/search", {
      query: capabilitySearchQuery(q, query),
    });
  }

  capability(slug: string): Promise<unknown> {
    return this.get(`/v1/capabilities/${normalizeCapabilitySlug(slug)}`);
  }

  capabilityCategories(): Promise<unknown> {
    return this.get("/v1/capabilities/categories");
  }

  async embed(text: string, options: EmbedOptions = {}): Promise<number[]> {
    const embedUrl = optionalTrimTrailingSlash(options.embedUrl ?? this.embedUrl);
    if (!embedUrl) {
      throw new Error("embed service URL required; pass embedUrl or set ZINCHA_EMBED_URL");
    }
    const response = await this.fetchImpl(`${embedUrl}/embed`, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ text }),
      signal: options.signal,
    });
    const bodyText = await response.text();
    let parsed: unknown;
    try {
      parsed = bodyText.length === 0 ? null : JSON.parse(bodyText);
    } catch (error) {
      throw new ZinchaApiError(response.status, `invalid JSON response: ${String(error)}`, bodyText);
    }
    if (!response.ok) {
      const body = parsed as { error?: unknown; message?: unknown } | null;
      const message = typeof body?.error === "string"
        ? body.error
        : typeof body?.message === "string"
          ? body.message
          : response.statusText;
      throw new ZinchaApiError(response.status, message, parsed);
    }
    try {
      return parseEmbedResponse(parsed);
    } catch (error) {
      throw new ZinchaApiError(response.status, String(error instanceof Error ? error.message : error), parsed);
    }
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

  submitTransactionBatch(signedTxHexes: Hex[]): Promise<SubmitBatchResult> {
    return this.post<SubmitBatchResult>("/v1/tx/submit/batch", {
      signed_transactions_hex: signedTxHexes.map(normalizeHexEven),
    });
  }

  async buildTransfer(signer: TransactionSigner, input: TransferInput): Promise<SignedTransaction> {
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
    const nonce = input.nonce ?? (await this.nonce(signer.address())).next_nonce;
    const chainId = input.chainId ?? chainInfo?.chain_id;
    if (!chainId) {
      throw new Error("chainId is required when chain info is not available");
    }
    const fee = input.feeMicroZin ?? estimateTransferFeeMicroZin(chainInfo?.next_base_fee ?? 0);
    let tx = createTransferTransaction(signer, {
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
    return signTransactionWith(tx, signer);
  }

  async transferAndSubmit(signer: TransactionSigner, input: TransferInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildTransfer(signer, input));
  }

  /**
   * Build, sign, and return an `agent_register` transaction. Auto-fetches
   * `chain_id` and `nonce` from the node when omitted, and pins the
   * transaction's validity window to the chain's current reference block.
   */
  async buildRegisterAgent(signer: TransactionSigner, input: RegisterAgentInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "agent_register", input, encodeAgentRegisterData(input));
  }

  /** Convenience: build + submit an `agent_register` transaction. */
  async registerAgentAndSubmit(signer: TransactionSigner, input: RegisterAgentInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildRegisterAgent(signer, input));
  }

  /** Build, sign, and return an `agent_update` transaction. */
  async buildUpdateAgent(signer: TransactionSigner, input: AgentUpdateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "agent_update", input, encodeAgentUpdateData(input));
  }

  /** Convenience: build + submit an `agent_update` transaction. */
  async updateAgentAndSubmit(signer: TransactionSigner, input: AgentUpdateInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateAgent(signer, input));
  }

  /** Build, sign, and return an `agent_deregister` transaction. */
  async buildDeregisterAgent(signer: TransactionSigner, input: AgentDeregisterInput = {}): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "agent_deregister", input, encodeAgentDeregisterData(input));
  }

  /** Convenience: build + submit an `agent_deregister` transaction. */
  async deregisterAgentAndSubmit(
    signer: TransactionSigner,
    input: AgentDeregisterInput = {},
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDeregisterAgent(signer, input));
  }

  /** Build, sign, and return a `capability_propose` transaction. */
  async buildProposeCapability(signer: TransactionSigner, input: CapabilityProposeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "capability_propose", input, encodeCapabilityProposeData(input));
  }

  /** Convenience: build + submit a `capability_propose` transaction. */
  async proposeCapabilityAndSubmit(signer: TransactionSigner, input: CapabilityProposeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildProposeCapability(signer, input));
  }

  /** Build, sign, and return a curator-only `capability_approve` transaction. */
  async buildApproveCapability(signer: TransactionSigner, input: CapabilityApproveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "capability_approve", input, encodeCapabilityApproveData(input));
  }

  /** Convenience: build + submit a curator-only `capability_approve` transaction. */
  async approveCapabilityAndSubmit(signer: TransactionSigner, input: CapabilityApproveInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildApproveCapability(signer, input));
  }

  /** Build, sign, and return a curator-only `capability_reject` transaction. */
  async buildRejectCapability(signer: TransactionSigner, input: CapabilityRejectInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "capability_reject", input, encodeCapabilityRejectData(input));
  }

  /** Convenience: build + submit a curator-only `capability_reject` transaction. */
  async rejectCapabilityAndSubmit(signer: TransactionSigner, input: CapabilityRejectInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildRejectCapability(signer, input));
  }

  /** Build, sign, and return a curator-only `capability_deprecate` transaction. */
  async buildDeprecateCapability(signer: TransactionSigner, input: CapabilityDeprecateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "capability_deprecate", input, encodeCapabilityDeprecateData(input));
  }

  /** Convenience: build + submit a curator-only `capability_deprecate` transaction. */
  async deprecateCapabilityAndSubmit(signer: TransactionSigner, input: CapabilityDeprecateInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDeprecateCapability(signer, input));
  }

  /**
   * Build, sign, and return a `task_submit` transaction. Auto-fetches
   * `chain_id` and `nonce` from the node when omitted, and pins the
   * transaction's validity window to the chain's current reference block.
   */
  async buildSubmitTask(signer: TransactionSigner, input: SubmitTaskInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "task_submit", input, encodeTaskSubmitData(input));
  }

  /** Convenience: build + submit a `task_submit` transaction. */
  async submitTaskAndSubmit(signer: TransactionSigner, input: SubmitTaskInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildSubmitTask(signer, input));
  }

  /** Build, sign, and return a `task_fulfill` transaction. */
  async buildFulfillTask(signer: TransactionSigner, input: TaskFulfillInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "task_fulfill", input, encodeTaskFulfillData(input));
  }

  /** Convenience: build + submit a `task_fulfill` transaction. */
  async fulfillTaskAndSubmit(signer: TransactionSigner, input: TaskFulfillInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildFulfillTask(signer, input));
  }

  /** Build, sign, and return a `task_accept` transaction. */
  async buildAcceptTask(signer: TransactionSigner, input: TaskAcceptInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "task_accept", input, encodeTaskAcceptData(input));
  }

  /** Convenience: build + submit a `task_accept` transaction. */
  async acceptTaskAndSubmit(signer: TransactionSigner, input: TaskAcceptInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildAcceptTask(signer, input));
  }

  /** Build, sign, and return a `task_dispute` transaction. */
  async buildDisputeTask(signer: TransactionSigner, input: TaskDisputeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "task_dispute", input, encodeTaskDisputeData(input));
  }

  /** Convenience: build + submit a `task_dispute` transaction. */
  async disputeTaskAndSubmit(signer: TransactionSigner, input: TaskDisputeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDisputeTask(signer, input));
  }

  /** Build, sign, and return a `task_resolve` transaction. */
  async buildResolveTask(signer: TransactionSigner, input: TaskResolveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "task_resolve", input, encodeTaskResolveData(input));
  }

  /** Convenience: build + submit a `task_resolve` transaction. */
  async resolveTaskAndSubmit(signer: TransactionSigner, input: TaskResolveInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildResolveTask(signer, input));
  }

  /** Build, sign, and return a `task_finalize` transaction. */
  async buildFinalizeTask(signer: TransactionSigner, input: TaskFinalizeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "task_finalize", input, encodeTaskFinalizeData(input));
  }

  /** Convenience: build + submit a `task_finalize` transaction. */
  async finalizeTaskAndSubmit(signer: TransactionSigner, input: TaskFinalizeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildFinalizeTask(signer, input));
  }

  /** Build, sign, and return a `task_cancel` transaction. */
  async buildCancelTask(signer: TransactionSigner, input: TaskCancelInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "task_cancel", input, encodeTaskCancelData(input));
  }

  /** Convenience: build + submit a `task_cancel` transaction. */
  async cancelTaskAndSubmit(signer: TransactionSigner, input: TaskCancelInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCancelTask(signer, input));
  }

  /** Build, sign, and return an escrow-funded `agreement_create` transaction. */
  async buildCreateAgreement(signer: TransactionSigner, input: AgreementCreateInput): Promise<SignedTransaction> {
    const proposer = normalizeAddress(signer.address());
    if (!input.parties.some((party) => normalizeAddress(party) === proposer)) {
      throw new Error("agreement proposer must be included in parties");
    }
    if (normalizeAddress(input.serviceProvider) === proposer) {
      throw new Error("agreement serviceProvider cannot be the proposer");
    }
    if (input.settlementApprover !== null && input.settlementApprover !== undefined) {
      const approver = normalizeAddress(input.settlementApprover);
      const settlementRecipients = input.settlementAllocations && input.settlementAllocations.length > 0
        ? input.settlementAllocations.map((allocation) => normalizeAddress(allocation.recipient))
        : [normalizeAddress(input.serviceProvider)];
      const invalidRecipient = approver !== proposer && settlementRecipients.includes(approver);
      if (invalidRecipient) {
        throw new Error("settlementApprover cannot be a non-proposer payout recipient");
      }
    }
    return this.buildTypedTransaction(
      signer,
      "agreement_create",
      { ...input, amountMicroZin: input.escrowAmount },
      encodeAgreementCreateData(input),
    );
  }

  /** Convenience: build + submit an `agreement_create` transaction. */
  async createAgreementAndSubmit(
    signer: TransactionSigner,
    input: AgreementCreateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCreateAgreement(signer, input));
  }

  async buildAcceptAgreement(signer: TransactionSigner, input: AgreementAcceptInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "agreement_accept", input, encodeAgreementAcceptData(input));
  }

  async acceptAgreementAndSubmit(
    signer: TransactionSigner,
    input: AgreementAcceptInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildAcceptAgreement(signer, input));
  }

  async buildExecuteAgreement(signer: TransactionSigner, input: AgreementExecuteInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "agreement_execute", input, encodeAgreementExecuteData(input));
  }

  async executeAgreementAndSubmit(
    signer: TransactionSigner,
    input: AgreementExecuteInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildExecuteAgreement(signer, input));
  }

  async buildDisputeAgreement(signer: TransactionSigner, input: AgreementDisputeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "agreement_dispute", input, encodeAgreementDisputeData(input));
  }

  async disputeAgreementAndSubmit(
    signer: TransactionSigner,
    input: AgreementDisputeInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDisputeAgreement(signer, input));
  }

  async buildResolveAgreement(signer: TransactionSigner, input: AgreementResolveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "agreement_resolve", input, encodeAgreementResolveData(input));
  }

  async resolveAgreementAndSubmit(
    signer: TransactionSigner,
    input: AgreementResolveInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildResolveAgreement(signer, input));
  }

  async buildCancelAgreement(signer: TransactionSigner, input: AgreementCancelInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "agreement_cancel", input, encodeAgreementCancelData(input));
  }

  async cancelAgreementAndSubmit(
    signer: TransactionSigner,
    input: AgreementCancelInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCancelAgreement(signer, input));
  }

  /** Build, sign, and return a `reputation_update` transaction. */
  async buildUpdateReputation(signer: TransactionSigner, input: ReputationUpdateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "reputation_update", input, encodeReputationUpdateData(input));
  }

  /** Convenience: build + submit a `reputation_update` transaction. */
  async updateReputationAndSubmit(signer: TransactionSigner, input: ReputationUpdateInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateReputation(signer, input));
  }

  /** Build, sign, and return a `token_create` transaction. */
  async buildCreateToken(signer: TransactionSigner, input: TokenCreateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "token_create", input, encodeTokenCreateData(input));
  }

  /** Convenience: build + submit a `token_create` transaction. */
  async createTokenAndSubmit(signer: TransactionSigner, input: TokenCreateInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCreateToken(signer, input));
  }

  /** Build, sign, and return a `token_transfer` transaction. */
  async buildTransferToken(signer: TransactionSigner, input: TokenTransferInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "token_transfer",
      input,
      encodeTokenTransferData(input),
      input.to,
    );
  }

  /** Convenience: build + submit a `token_transfer` transaction. */
  async transferTokenAndSubmit(signer: TransactionSigner, input: TokenTransferInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildTransferToken(signer, input));
  }

  /** Build, sign, and return a `token_approve` transaction. */
  async buildApproveToken(signer: TransactionSigner, input: TokenApproveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "token_approve",
      input,
      encodeTokenApproveData(input),
      input.spender,
    );
  }

  /** Convenience: build + submit a `token_approve` transaction. */
  async approveTokenAndSubmit(signer: TransactionSigner, input: TokenApproveInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildApproveToken(signer, input));
  }

  /** Build, sign, and return a `token_mint` transaction. */
  async buildMintToken(signer: TransactionSigner, input: TokenMintInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "token_mint",
      input,
      encodeTokenMintData(input),
      input.to,
    );
  }

  /** Convenience: build + submit a `token_mint` transaction. */
  async mintTokenAndSubmit(signer: TransactionSigner, input: TokenMintInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildMintToken(signer, input));
  }

  /** Build, sign, and return a `token_burn` transaction. */
  async buildBurnToken(signer: TransactionSigner, input: TokenBurnInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "token_burn", input, encodeTokenBurnData(input));
  }

  /** Convenience: build + submit a `token_burn` transaction. */
  async burnTokenAndSubmit(signer: TransactionSigner, input: TokenBurnInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildBurnToken(signer, input));
  }

  /** Build, sign, and return a `tool_register` transaction. */
  async buildRegisterTool(signer: TransactionSigner, input: ToolRegisterInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_register", input, encodeToolRegisterData(input));
  }

  /** Convenience: build + submit a `tool_register` transaction. */
  async registerToolAndSubmit(signer: TransactionSigner, input: ToolRegisterInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildRegisterTool(signer, input));
  }

  /** Build, sign, and return a `tool_update` transaction. */
  async buildUpdateTool(signer: TransactionSigner, input: ToolUpdateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_update", input, encodeToolUpdateData(input));
  }

  /** Convenience: build + submit a `tool_update` transaction. */
  async updateToolAndSubmit(signer: TransactionSigner, input: ToolUpdateInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateTool(signer, input));
  }

  /** Build, sign, and return a `tool_invoke` transaction. */
  async buildInvokeTool(signer: TransactionSigner, input: ToolInvokeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_invoke", input, encodeToolInvokeData(input));
  }

  /** Convenience: build + submit a `tool_invoke` transaction. */
  async invokeToolAndSubmit(signer: TransactionSigner, input: ToolInvokeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildInvokeTool(signer, input));
  }

  /** Build, sign, and return a `tool_deregister` transaction. */
  async buildDeregisterTool(signer: TransactionSigner, input: ToolDeregisterInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_deregister", input, encodeToolDeregisterData(input));
  }

  /** Convenience: build + submit a `tool_deregister` transaction. */
  async deregisterToolAndSubmit(signer: TransactionSigner, input: ToolDeregisterInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDeregisterTool(signer, input));
  }

  async buildSubmitToolResult(signer: TransactionSigner, input: ToolResultSubmitInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_result_submit", input, encodeToolResultSubmitData(input));
  }

  async submitToolResultAndSubmit(signer: TransactionSigner, input: ToolResultSubmitInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildSubmitToolResult(signer, input));
  }

  async buildAcceptToolResult(signer: TransactionSigner, input: ToolResultAcceptInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_result_accept", input, encodeToolResultAcceptData(input));
  }

  async acceptToolResultAndSubmit(signer: TransactionSigner, input: ToolResultAcceptInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildAcceptToolResult(signer, input));
  }

  async buildDisputeToolResult(signer: TransactionSigner, input: ToolResultDisputeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_result_dispute", input, encodeToolResultDisputeData(input));
  }

  async disputeToolResultAndSubmit(signer: TransactionSigner, input: ToolResultDisputeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDisputeToolResult(signer, input));
  }

  async buildResolveToolResult(signer: TransactionSigner, input: ToolResultResolveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_result_resolve", input, encodeToolResultResolveData(input));
  }

  async resolveToolResultAndSubmit(signer: TransactionSigner, input: ToolResultResolveInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildResolveToolResult(signer, input));
  }

  async buildExpireToolJob(signer: TransactionSigner, input: ToolJobExpireInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_job_expire", input, encodeToolJobExpireData(input));
  }

  async expireToolJobAndSubmit(signer: TransactionSigner, input: ToolJobExpireInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildExpireToolJob(signer, input));
  }

  async buildReportToolUsage(signer: TransactionSigner, input: ToolUsageReportInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_usage_report", input, encodeToolUsageReportData(input));
  }

  async reportToolUsageAndSubmit(signer: TransactionSigner, input: ToolUsageReportInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildReportToolUsage(signer, input));
  }

  async buildAcceptToolUsage(signer: TransactionSigner, input: ToolUsageAcceptInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_usage_accept", input, encodeToolUsageAcceptData(input));
  }

  async acceptToolUsageAndSubmit(signer: TransactionSigner, input: ToolUsageAcceptInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildAcceptToolUsage(signer, input));
  }

  async buildDisputeToolUsage(signer: TransactionSigner, input: ToolUsageDisputeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_usage_dispute", input, encodeToolUsageDisputeData(input));
  }

  async disputeToolUsageAndSubmit(signer: TransactionSigner, input: ToolUsageDisputeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDisputeToolUsage(signer, input));
  }

  async buildResolveToolUsage(signer: TransactionSigner, input: ToolUsageResolveInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_usage_resolve", input, encodeToolUsageResolveData(input));
  }

  async resolveToolUsageAndSubmit(signer: TransactionSigner, input: ToolUsageResolveInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildResolveToolUsage(signer, input));
  }

  async buildExpireToolUsage(signer: TransactionSigner, input: ToolUsageExpireInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_usage_expire", input, encodeToolUsageExpireData(input));
  }

  async expireToolUsageAndSubmit(signer: TransactionSigner, input: ToolUsageExpireInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildExpireToolUsage(signer, input));
  }

  async buildCreateToolSubscriptionPlan(
    signer: TransactionSigner,
    input: ToolSubscriptionPlanCreateInput,
  ): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "tool_subscription_plan_create",
      input,
      encodeToolSubscriptionPlanCreateData(input),
    );
  }

  async createToolSubscriptionPlanAndSubmit(
    signer: TransactionSigner,
    input: ToolSubscriptionPlanCreateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCreateToolSubscriptionPlan(signer, input));
  }

  async buildUpdateToolSubscriptionPlan(
    signer: TransactionSigner,
    input: ToolSubscriptionPlanUpdateInput,
  ): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "tool_subscription_plan_update",
      input,
      encodeToolSubscriptionPlanUpdateData(input),
    );
  }

  async updateToolSubscriptionPlanAndSubmit(
    signer: TransactionSigner,
    input: ToolSubscriptionPlanUpdateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateToolSubscriptionPlan(signer, input));
  }

  async buildStartToolSubscription(signer: TransactionSigner, input: ToolSubscriptionStartInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_subscription_start", input, encodeToolSubscriptionStartData(input));
  }

  async startToolSubscriptionAndSubmit(
    signer: TransactionSigner,
    input: ToolSubscriptionStartInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildStartToolSubscription(signer, input));
  }

  async buildTopUpToolSubscription(signer: TransactionSigner, input: ToolSubscriptionTopUpInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_subscription_top_up", input, encodeToolSubscriptionTopUpData(input));
  }

  async topUpToolSubscriptionAndSubmit(
    signer: TransactionSigner,
    input: ToolSubscriptionTopUpInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildTopUpToolSubscription(signer, input));
  }

  async buildCancelToolSubscription(signer: TransactionSigner, input: ToolSubscriptionCancelInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_subscription_cancel", input, encodeToolSubscriptionCancelData(input));
  }

  async cancelToolSubscriptionAndSubmit(
    signer: TransactionSigner,
    input: ToolSubscriptionCancelInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCancelToolSubscription(signer, input));
  }

  async buildResumeToolSubscription(signer: TransactionSigner, input: ToolSubscriptionResumeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_subscription_resume", input, encodeToolSubscriptionResumeData(input));
  }

  async resumeToolSubscriptionAndSubmit(
    signer: TransactionSigner,
    input: ToolSubscriptionResumeInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildResumeToolSubscription(signer, input));
  }

  async buildRenewToolSubscription(signer: TransactionSigner, input: ToolSubscriptionRenewInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(signer, "tool_subscription_renew", input, encodeToolSubscriptionRenewData(input));
  }

  async renewToolSubscriptionAndSubmit(
    signer: TransactionSigner,
    input: ToolSubscriptionRenewInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildRenewToolSubscription(signer, input));
  }

  async buildDeployContract(signer: TransactionSigner, input: ContractDeployInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "contract_deploy",
      input,
      encodeContractDeployData(input),
    );
  }

  async deployContractAndSubmit(
    signer: TransactionSigner,
    input: ContractDeployInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDeployContract(signer, input));
  }

  async buildCallContract(signer: TransactionSigner, input: ContractCallInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "contract_call",
      input,
      encodeContractCallData(input),
    );
  }

  async callContractAndSubmit(
    signer: TransactionSigner,
    input: ContractCallInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCallContract(signer, input));
  }

  async buildVerifyContract(signer: TransactionSigner, input: ContractVerifyInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "contract_verify",
      input,
      encodeContractVerifyData(input),
    );
  }

  async verifyContractAndSubmit(
    signer: TransactionSigner,
    input: ContractVerifyInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildVerifyContract(signer, input));
  }

  async buildPublishContractAbi(signer: TransactionSigner, input: ContractPublishAbiInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "contract_publish_abi",
      input,
      encodeContractPublishAbiData(input),
    );
  }

  async publishContractAbiAndSubmit(
    signer: TransactionSigner,
    input: ContractPublishAbiInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildPublishContractAbi(signer, input));
  }

  async buildUpdateContractRoute(signer: TransactionSigner, input: ContractRouteUpdateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "contract_route_update",
      input,
      encodeContractRouteUpdateData(input),
    );
  }

  async updateContractRouteAndSubmit(
    signer: TransactionSigner,
    input: ContractRouteUpdateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateContractRoute(signer, input));
  }

  async buildCallContractRoute(signer: TransactionSigner, input: ContractRouteCallInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "contract_route_call",
      input,
      encodeContractRouteCallData(input),
    );
  }

  async callContractRouteAndSubmit(
    signer: TransactionSigner,
    input: ContractRouteCallInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCallContractRoute(signer, input));
  }

  async buildDeactivateContract(signer: TransactionSigner, input: ContractDeactivateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "contract_deactivate",
      input,
      encodeContractDeactivateData(input),
    );
  }

  async deactivateContractAndSubmit(
    signer: TransactionSigner,
    input: ContractDeactivateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildDeactivateContract(signer, input));
  }

  async buildRegisterValidator(signer: TransactionSigner, input: ValidatorRegisterInput): Promise<SignedTransaction> {
    const vrfPublicKey = input.vrfPublicKey ?? signer.publicKeyHex();
    return this.buildTypedTransaction(
      signer,
      "validator_register",
      { ...input, amountMicroZin: input.stakeMicroZin },
      encodeValidatorRegisterData({ ...input, vrfPublicKey }),
    );
  }

  async registerValidatorAndSubmit(
    signer: TransactionSigner,
    input: ValidatorRegisterInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildRegisterValidator(signer, input));
  }

  async buildUpdateValidator(signer: TransactionSigner, input: ValidatorUpdateInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "validator_update",
      input,
      encodeValidatorUpdateData(input),
    );
  }

  async updateValidatorAndSubmit(
    signer: TransactionSigner,
    input: ValidatorUpdateInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUpdateValidator(signer, input));
  }

  async buildExitValidator(signer: TransactionSigner, input: ValidatorExitInput = {}): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "validator_exit",
      input,
      encodeValidatorExitData(input),
    );
  }

  async exitValidatorAndSubmit(
    signer: TransactionSigner,
    input: ValidatorExitInput = {},
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildExitValidator(signer, input));
  }

  async buildCommitValidatorVrf(
    signer: TransactionSigner,
    input: ValidatorVrfCommitInput,
  ): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "validator_vrf_commit",
      input,
      encodeValidatorVrfCommitData(input),
    );
  }

  async commitValidatorVrfAndSubmit(
    signer: TransactionSigner,
    input: ValidatorVrfCommitInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildCommitValidatorVrf(signer, input));
  }

  async buildContributeValidatorVrf(
    signer: TransactionSigner,
    input: ValidatorVrfContributionInput,
  ): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "validator_vrf_contribution",
      input,
      encodeValidatorVrfContributionData(input),
    );
  }

  async contributeValidatorVrfAndSubmit(
    signer: TransactionSigner,
    input: ValidatorVrfContributionInput,
  ): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildContributeValidatorVrf(signer, input));
  }

  async buildStake(signer: TransactionSigner, input: StakeInput): Promise<SignedTransaction> {
    return this.buildTypedTransaction(
      signer,
      "stake",
      { ...input, amountMicroZin: input.amountMicroZin },
      encodeStakeData(input),
    );
  }

  async stakeAndSubmit(signer: TransactionSigner, input: StakeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildStake(signer, input));
  }

  async buildUnstake(signer: TransactionSigner, input: UnstakeInput): Promise<SignedTransaction> {
    if (input.target === "requester_auto_match") {
      throw new Error("requester_auto_match stake cannot be unstaked");
    }
    return this.buildTypedTransaction(
      signer,
      "unstake",
      { ...input, amountMicroZin: input.amountMicroZin },
      encodeUnstakeData(input),
    );
  }

  async unstakeAndSubmit(signer: TransactionSigner, input: UnstakeInput): Promise<SubmitTransactionResponse> {
    return this.submitSignedTransaction(await this.buildUnstake(signer, input));
  }

  /**
   * Internal helper: assemble + sign a typed transaction. Mirrors the
   * chain-aware behavior of `buildTransfer` for any tx type whose data
   * payload has already been bincode-encoded.
   */
  private async buildTypedTransaction(
    signer: TransactionSigner,
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
    recipient?: string,
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
    const nonce = input.nonce ?? (await this.nonce(signer.address())).next_nonce;

    let tx = createSignableTransaction({
      txType,
      sender: signer.address(),
      recipient,
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

    return signTransactionWith(tx, signer);
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

  agents(query?: CursorPageQuery): Promise<unknown> {
    return this.get("/v1/agents", { query: cursorPageQuery(query) });
  }

  arbitrators(query?: CursorPageQuery): Promise<unknown> {
    return this.get("/v1/arbitrators", { query: cursorPageQuery(query) });
  }

  marketRates(query?: CursorPageQuery): Promise<MarketRateListResponse> {
    return this.get<MarketRateListResponse>("/v1/market-rates", {
      query: cursorPageQuery(query),
    });
  }

  agent(address: string): Promise<unknown> {
    return this.get(`/v1/agents/${normalizeAddress(address)}`);
  }

  agentLifecycleEvents(
    address: string,
    query?: Record<string, string | number | boolean | undefined>,
  ): Promise<unknown> {
    return this.get(`/v1/agents/${normalizeAddress(address)}/lifecycle-events`, { query });
  }

  agentReputationEvents(
    address: string,
    query?: Record<string, string | number | boolean | undefined>,
  ): Promise<unknown> {
    return this.get(`/v1/agents/${normalizeAddress(address)}/reputation-events`, { query });
  }

  agentReputationHistory(
    address: string,
    query?: Record<string, string | number | boolean | undefined>,
  ): Promise<unknown> {
    return this.get(`/v1/agents/${normalizeAddress(address)}/reputation-history`, { query });
  }

  requesterReputation(address: string): Promise<unknown> {
    return this.get(`/v1/requesters/${normalizeAddress(address)}`);
  }

  requesterReputationEvents(
    address: string,
    query?: Record<string, string | number | boolean | undefined>,
  ): Promise<unknown> {
    return this.get(`/v1/requesters/${normalizeAddress(address)}/reputation-events`, { query });
  }

  requesterReputationHistory(
    address: string,
    query?: Record<string, string | number | boolean | undefined>,
  ): Promise<unknown> {
    return this.get(`/v1/requesters/${normalizeAddress(address)}/reputation-history`, { query });
  }

  pendingTasks(query?: PendingTaskListQuery): Promise<unknown> {
    return this.get("/v1/tasks/pending", { query: pendingTaskListQuery(query) });
  }

  taskOpportunity(id: Hex): Promise<unknown> {
    return this.get(`/v1/tasks/${normalizeHash(id)}/opportunity`);
  }

  taskReputationEvents(
    id: Hex,
    query?: Record<string, string | number | boolean | undefined>,
  ): Promise<unknown> {
    return this.get(`/v1/tasks/${normalizeHash(id)}/reputation-events`, { query });
  }

  task(id: Hex, options: Omit<RequestOptions, "body" | "query" | "signed"> = {}): Promise<unknown> {
    return this.get(`/v1/tasks/${normalizeHash(id)}`, { ...options, signed: true });
  }

  agreement(id: Hex, options: Omit<RequestOptions, "body" | "query" | "signed"> = {}): Promise<unknown> {
    return this.get(`/v1/agreements/${normalizeHash(id)}`, { ...options, signed: true });
  }

  agreementsByParty(
    address: string,
    query?: ParticipantWorkflowQuery,
    options: Omit<RequestOptions, "body" | "query" | "signed"> = {},
  ): Promise<unknown> {
    return this.get(`/v1/agreements/party/${normalizeAddress(address)}`, {
      ...options,
      signed: true,
      query: participantWorkflowQuery(query),
    });
  }

  agreementsByArbitrator(
    address: string,
    query?: ParticipantWorkflowQuery,
    options: Omit<RequestOptions, "body" | "query" | "signed"> = {},
  ): Promise<unknown> {
    return this.get(`/v1/agreements/arbitrator/${normalizeAddress(address)}`, {
      ...options,
      signed: true,
      query: participantWorkflowQuery(query),
    });
  }

  toolJob(id: Hex, options: Omit<RequestOptions, "body" | "query" | "signed"> = {}): Promise<unknown> {
    return this.get(`/v1/tool-jobs/${normalizeHash(id)}`, { ...options, signed: true });
  }

  toolJobsByRequester(
    address: string,
    query?: ParticipantWorkflowQuery,
    options: Omit<RequestOptions, "body" | "query" | "signed"> = {},
  ): Promise<unknown> {
    return this.get(`/v1/tool-jobs/requester/${normalizeAddress(address)}`, {
      ...options,
      signed: true,
      query: participantWorkflowQuery(query),
    });
  }

  toolJobsByProvider(
    address: string,
    query?: ParticipantWorkflowQuery,
    options: Omit<RequestOptions, "body" | "query" | "signed"> = {},
  ): Promise<unknown> {
    return this.get(`/v1/tool-jobs/provider/${normalizeAddress(address)}`, {
      ...options,
      signed: true,
      query: participantWorkflowQuery(query),
    });
  }

  toolUsageSession(
    id: Hex,
    options: Omit<RequestOptions, "body" | "query" | "signed"> = {},
  ): Promise<unknown> {
    return this.get(`/v1/tool-usage-sessions/${normalizeHash(id)}`, { ...options, signed: true });
  }

  toolUsageSessionsByRequester(
    address: string,
    query?: ParticipantWorkflowQuery,
    options: Omit<RequestOptions, "body" | "query" | "signed"> = {},
  ): Promise<unknown> {
    return this.get(`/v1/tool-usage-sessions/requester/${normalizeAddress(address)}`, {
      ...options,
      signed: true,
      query: participantWorkflowQuery(query),
    });
  }

  toolUsageSessionsByProvider(
    address: string,
    query?: ParticipantWorkflowQuery,
    options: Omit<RequestOptions, "body" | "query" | "signed"> = {},
  ): Promise<unknown> {
    return this.get(`/v1/tool-usage-sessions/provider/${normalizeAddress(address)}`, {
      ...options,
      signed: true,
      query: participantWorkflowQuery(query),
    });
  }

  tools(query?: CursorPageQuery): Promise<unknown> {
    return this.get("/v1/tools", { query: cursorPageQuery(query) });
  }

  contracts(query?: CursorPageQuery): Promise<unknown> {
    return this.get("/v1/contracts", { query: cursorPageQuery(query) });
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

  tokens(query?: CursorPageQuery): Promise<unknown> {
    return this.get("/v1/tokens", { query: cursorPageQuery(query) });
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

  async signedRequestHeaders(method: string, path: string, body?: unknown): Promise<Record<string, string>> {
    if (!this.signer) {
      throw new Error("signed request requires a client signer");
    }
    const payload = body === undefined ? "" : JSON.stringify(body);
    return signedRequestHeadersAsync(this.signer, {
      method,
      requestTarget: path,
      body: payload,
    });
  }
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function optionalTrimTrailingSlash(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimTrailingSlash(trimmed) : undefined;
}

function embedUrlFromEnv(): string | undefined {
  const env = (globalThis as unknown as {
    process?: { env?: Record<string, string | undefined> };
  }).process?.env;
  return env?.ZINCHA_EMBED_URL;
}

function parseEmbedResponse(value: unknown): number[] {
  if (typeof value !== "object" || value === null || !Array.isArray((value as { embedding?: unknown }).embedding)) {
    throw new Error("embed service response must include an embedding array");
  }
  const embedding = (value as { embedding: unknown[] }).embedding;
  if (embedding.length === 0) {
    throw new Error("embed service returned an empty embedding");
  }
  return embedding.map((item, index) => {
    if (typeof item !== "number" || !Number.isFinite(item)) {
      throw new Error(`embed service returned a non-finite embedding value at index ${index}`);
    }
    return item;
  });
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

function participantWorkflowQuery(query?: ParticipantWorkflowQuery): RequestOptions["query"] {
  return {
    limit: query?.limit,
    cursor: query?.cursor,
  };
}

function cursorPageQuery(query?: CursorPageQuery): RequestOptions["query"] {
  return {
    cursor: query?.cursor,
    limit: query?.limit,
  };
}

function pendingTaskListQuery(query?: PendingTaskListQuery): RequestOptions["query"] {
  return {
    cursor: query?.cursor,
    limit: query?.limit,
    discover_capability: query?.discover_capability,
    discover_min_fee: query?.discover_min_fee,
    discover_fee: query?.discover_fee,
  };
}

function capabilityListQuery(query?: CapabilityListQuery): RequestOptions["query"] {
  return {
    limit: query?.limit,
    cursor: query?.cursor,
    status: query?.status,
    category: query?.category,
    parent: query?.parent,
  };
}

function capabilitySearchQuery(
  q: string,
  query?: CapabilitySearchQuery,
): RequestOptions["query"] {
  return {
    q,
    limit: query?.limit,
    cursor: query?.cursor,
    status: query?.status,
    category: query?.category,
  };
}

export function validateCapabilitySlug(slug: string): boolean {
  return /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){1,7}$/.test(slug)
    && slug.length <= 128;
}

export function normalizeCapabilitySlug(slug: string): string {
  const normalized = slug.trim().toLowerCase();
  if (!validateCapabilitySlug(normalized)) {
    throw new Error("invalid capability slug");
  }
  return normalized;
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
