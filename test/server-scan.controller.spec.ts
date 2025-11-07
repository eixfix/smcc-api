import { Role, ServerScanStatus } from '@prisma/client';

import type { AuthenticatedUser } from '../src/common/types/auth-user';
import type { AgentSessionContext } from '../src/modules/server/guards/agent-session.guard';
import { QueueServerScanDto } from '../src/modules/server/dto/queue-server-scan.dto';
import { ReportServerScanDto } from '../src/modules/server/dto/report-server-scan.dto';
import { TelemetryPayloadDto } from '../src/modules/server/dto/telemetry-payload.dto';
import { ServerScanController } from '../src/modules/server/server-scan.controller';
import type { ServerScanService } from '../src/modules/server/server-scan.service';

const mockUser: AuthenticatedUser = {
  userId: 'user_1',
  email: 'owner@example.com',
  role: Role.OWNER
};

const mockAgent: AgentSessionContext = {
  agentId: 'agent_1',
  serverId: 'srv_1',
  organizationId: 'org_1'
};

describe('ServerScanController', () => {
  let controller: ServerScanController;
  let service: jest.Mocked<ServerScanService>;

  beforeEach(() => {
    service = {
      queueScan: jest.fn(),
      listScans: jest.fn(),
      getNextQueuedScan: jest.fn(),
      submitScanReport: jest.fn(),
      ingestTelemetry: jest.fn()
    } as unknown as jest.Mocked<ServerScanService>;

    controller = new ServerScanController(service);
  });

  it('queues scan', async () => {
    const payload: QueueServerScanDto = { playbook: 'baseline' };
    await controller.queueScan('srv_1', payload, mockUser);
    expect(service.queueScan).toHaveBeenCalledWith('srv_1', payload, mockUser);
  });

  it('lists scans', async () => {
    await controller.listScans('srv_1', mockUser);
    expect(service.listScans).toHaveBeenCalledWith('srv_1', mockUser);
  });

  it('fetches next agent job', async () => {
    await controller.fetchNext(mockAgent);
    expect(service.getNextQueuedScan).toHaveBeenCalledWith(mockAgent);
  });

  it('submits scan report', async () => {
    const payload: ReportServerScanDto = {
      status: ServerScanStatus.COMPLETED
    };
    await controller.submitReport('scan_1', payload, mockAgent);
    expect(service.submitScanReport).toHaveBeenCalledWith(mockAgent, 'scan_1', payload);
  });

  it('ingests telemetry snapshot', async () => {
    const payload: TelemetryPayloadDto = { cpuPercent: 30 };
    await controller.ingestTelemetry(payload, mockAgent);
    expect(service.ingestTelemetry).toHaveBeenCalledWith(mockAgent, payload);
  });
});
