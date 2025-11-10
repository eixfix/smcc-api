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
}
export declare function buildAgentBootstrapTemplate({ apiUrl, configPath, metadataPath, binaryPath, agentVersion, defaultUpdateIntervalMinutes, derivedKey, installNonce, logPrefix }: AgentBootstrapTemplateOptions): string;
export {};
//# sourceMappingURL=agent-bootstrap.template.d.ts.map