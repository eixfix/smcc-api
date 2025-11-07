import { IsInt, Min } from 'class-validator';

export class UpdateOrganizationCreditsDto {
  @IsInt()
  @Min(1)
  amount!: number;
}
