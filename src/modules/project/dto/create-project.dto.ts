import { IsOptional, IsString, IsUrl, Length } from 'class-validator';

export class CreateProjectDto {
  @IsString()
  @Length(3, 80)
  name!: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsUrl({ require_tld: false })
  uptimeWebhookUrl?: string;
}
