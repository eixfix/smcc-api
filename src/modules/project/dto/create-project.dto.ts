import { IsOptional, IsString, Length } from 'class-validator';

export class CreateProjectDto {
  @IsString()
  @Length(3, 80)
  name!: string;

  @IsOptional()
  @IsString()
  description?: string;
}
