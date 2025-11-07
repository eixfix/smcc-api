import { IsDateString, IsOptional } from 'class-validator';

export class CreateServerAgentDto {
  @IsOptional()
  @IsDateString()
  expiresAt?: string;
}
