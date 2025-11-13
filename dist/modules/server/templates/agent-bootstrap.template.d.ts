interface AgentBootstrapTemplateOptions {
    apiUrl: string;
    configPath: string;
    metadataPath: string;
    binaryPath: string;
    agentVersion: string;
    defaultUpdateIntervalMinutes: number;
    derivedKey: string;
    installNonce: string;
    logPrefix: string;
    configSignatureKey: string;
    updateSignatureKey: string;
    configRefreshIntervalMinutes: number;
    playbookConfigPath: string;
    playbookTimeoutSeconds: number;
}
export declare function buildAgentBootstrapTemplate({ apiUrl, configPath, metadataPath, binaryPath, agentVersion, defaultUpdateIntervalMinutes, derivedKey, installNonce, logPrefix, configSignatureKey, updateSignatureKey, configRefreshIntervalMinutes, playbookConfigPath, playbookTimeoutSeconds }: AgentBootstrapTemplateOptions): string;
export {};
//# sourceMappingURL=agent-bootstrap.template.d.ts.map