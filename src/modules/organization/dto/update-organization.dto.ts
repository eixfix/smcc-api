import { IsOptional, IsString, IsUrl, Length, Matches } from 'class-validator';

export class UpdateOrganizationDto {
  @IsOptional()
  @IsString()
  @Length(3, 60)
  name?: string;

  @IsOptional()
  @IsString()
  @Matches(/^[a-z0-9-]+$/, {
    message: 'Slug can only include lowercase letters, numbers, and hyphens.'
  })
  slug?: string;

  @IsOptional()
  @IsUrl({ require_tld: false })
  uptimeWebhookUrl?: string;
}
