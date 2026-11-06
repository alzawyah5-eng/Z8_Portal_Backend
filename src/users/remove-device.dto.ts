import { IsString, MaxLength, MinLength } from 'class-validator';

export class RemoveDeviceDto {
  @IsString()
  @MinLength(20)
  @MaxLength(4096)
  token!: string;
}
