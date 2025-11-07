import { IsOptional, IsString, IsUrl, MaxLength } from 'class-validator';

export class CheckEndpointDto {
  @IsString()
  organizationId!: string;

  @IsUrl({ require_protocol: true, protocols: ['http', 'https'] })
  url!: string;

  @IsOptional()
  @IsString()
  @MaxLength(200)
  note?: string;
}
