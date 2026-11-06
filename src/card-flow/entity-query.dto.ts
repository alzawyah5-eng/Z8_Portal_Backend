import { IsObject, IsOptional, IsString, MaxLength, Min } from 'class-validator';

export class EntityQueryDto {
  @IsOptional()
  @IsObject()
  filter?: Record<string, unknown>;

  @IsOptional()
  @IsString()
  @MaxLength(80)
  sort?: string;

  @IsOptional()
  @Min(1)
  limit?: number;

  @IsOptional()
  @IsString()
  @MaxLength(256)
  cursor?: string;
}

export class EntityDataDto {
  @IsObject()
  data!: Record<string, unknown>;
}

export class EntityUpdateManyDto {
  @IsObject()
  filter!: Record<string, unknown>;

  @IsObject()
  update!: Record<string, unknown>;
}
