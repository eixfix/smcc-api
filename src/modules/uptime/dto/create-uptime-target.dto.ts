import { IsBoolean, IsEnum, IsInt, IsOptional, IsString, IsUrl, Max, Min } from 'class-validator';
import { UptimeProtocol, UptimeSensitivity } from '@prisma/client';

export class CreateUptimeTargetDto {
  @IsString()
  label!: string;

  @IsUrl({ require_tld: false })
  url!: string;

  @IsOptional()
  @IsEnum(UptimeProtocol)
  protocol?: UptimeProtocol;

  @IsOptional()
  @IsString()
  region?: string;

  @IsOptional()
  @IsEnum(UptimeSensitivity)
  sensitivity?: UptimeSensitivity;

  @IsOptional()
  @IsInt()
  @Min(60)
  @Max(86400)
  checkIntervalSeconds?: number;

  @IsOptional()
  @IsInt()
  @Min(500)
  @Max(60000)
  requestTimeoutMs?: number;

  @IsOptional()
  @IsInt()
  @Min(100)
  @Max(599)
  expectedStatus?: number;

  @IsOptional()
  @IsString()
  projectId?: string;

  @IsOptional()
  @IsString()
  serverId?: string;

  @IsOptional()
  @IsUrl({ require_tld: false })
  alertWebhookUrl?: string;

  @IsOptional()
  @IsBoolean()
  isPaused?: boolean;
}
