import {
  IsBoolean,
  IsNotEmpty,
  IsOptional,
  IsString,
  ValidateIf
} from 'class-validator';

export class CreateAgentUpdateManifestDto {
  @IsString()
  @IsNotEmpty()
  version!: string;

  @IsString()
  @IsNotEmpty()
  channel!: string;

  @ValidateIf((dto: CreateAgentUpdateManifestDto) => !dto.inlineSourceB64)
  @IsString()
  @IsNotEmpty()
  downloadUrl?: string;

  @ValidateIf((dto: CreateAgentUpdateManifestDto) => !dto.downloadUrl)
  @IsString()
  @IsNotEmpty()
  inlineSourceB64?: string;

  @IsOptional()
  @IsString()
  checksumAlgorithm?: string;

  @IsOptional()
  @IsString()
  checksumValue?: string;

  @IsOptional()
  @IsBoolean()
  restartRequired?: boolean;

  @IsOptional()
  @IsString()
  minConfigVersion?: string;

  @IsOptional()
  @IsString()
  notes?: string;
}
