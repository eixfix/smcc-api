import { IsEnum, IsOptional, IsString, IsUrl } from 'class-validator';
import { UptimeReason, UptimeState } from '@prisma/client';

export class TestWebhookDto {
  @IsOptional()
  @IsUrl({ require_tld: false })
  webhookUrl?: string;

  @IsOptional()
  @IsEnum(UptimeState)
  state?: UptimeState;

  @IsOptional()
  @IsEnum(UptimeReason)
  reason?: UptimeReason;

  @IsOptional()
  @IsString()
  reasonDetail?: string;
}
