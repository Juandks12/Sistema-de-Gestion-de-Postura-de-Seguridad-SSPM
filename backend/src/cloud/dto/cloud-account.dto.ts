import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { CloudAuthType, CloudProvider } from '@prisma/client';
import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';

export class CreateCloudAccountDto {
  @ApiProperty({ enum: CloudProvider, example: CloudProvider.AWS })
  @IsEnum(CloudProvider)
  provider!: CloudProvider;

  @ApiProperty({ example: 'AWS Producción Principal' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(150)
  name!: string;

  @ApiProperty({ enum: CloudAuthType, example: CloudAuthType.ROLE_ARN })
  @IsEnum(CloudAuthType)
  authType!: CloudAuthType;

  @ApiProperty({
    description: 'ID de cuenta de AWS (12 dígitos) o Subscription ID de Azure (UUID)',
    example: '123456789012',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  accountOrSubscriptionId!: string;

  @ApiPropertyOptional({ description: 'Tenant ID de Microsoft Entra ID (para Azure)' })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  azureTenantId?: string;

  @ApiPropertyOptional({ description: 'Application (Client) ID del Service Principal en Azure' })
  @IsOptional()
  @IsString()
  @MaxLength(150)
  azureClientId?: string;

  @ApiPropertyOptional({ description: 'Client Secret del Service Principal en Azure' })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  azureClientSecret?: string;

  @ApiPropertyOptional({
    description: 'ARN del rol IAM Cross-Account en AWS',
    example: 'arn:aws:iam::123456789012:role/SSPM-Cloud-Auditor-Role',
  })
  @IsOptional()
  @IsString()
  @MaxLength(255)
  awsRoleArn?: string;

  @ApiPropertyOptional({
    description: 'External ID para relación de confianza IAM en AWS',
  })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  awsExternalId?: string;

  @ApiPropertyOptional({ description: 'AWS Access Key ID (para modo ACCESS_KEYS o salto STS)' })
  @IsOptional()
  @IsString()
  @MaxLength(150)
  awsAccessKeyId?: string;

  @ApiPropertyOptional({ description: 'AWS Secret Access Key' })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  awsSecretAccessKey?: string;

  @ApiPropertyOptional({ description: 'AWS Session Token temporal opcional' })
  @IsOptional()
  @IsString()
  awsSessionToken?: string;

  @ApiPropertyOptional({
    description: 'Regiones habilitadas para auditoría',
    example: ['us-east-1', 'us-west-2'],
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  monitoredRegions?: string[];

  @ApiPropertyOptional({
    description: 'Si es true (por defecto), verifica la conectividad al registrar la cuenta',
    default: true,
  })
  @IsOptional()
  @IsBoolean()
  verifyOnCreate?: boolean;
}

export class UpdateCloudAccountDto {
  @ApiPropertyOptional({ example: 'AWS Producción Actualizado' })
  @IsOptional()
  @IsString()
  @MaxLength(150)
  name?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(255)
  awsRoleArn?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(150)
  awsAccessKeyId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(500)
  awsSecretAccessKey?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsSessionToken?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(150)
  azureClientId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(500)
  azureClientSecret?: string;

  @ApiPropertyOptional({ type: [String] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  monitoredRegions?: string[];
}

export class TestCloudConnectionDto {
  @ApiProperty({ enum: CloudProvider })
  @IsEnum(CloudProvider)
  provider!: CloudProvider;

  @ApiProperty({ enum: CloudAuthType })
  @IsEnum(CloudAuthType)
  authType!: CloudAuthType;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  accountOrSubscriptionId!: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  azureTenantId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  azureClientId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  azureClientSecret?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsRoleArn?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsExternalId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsAccessKeyId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsSecretAccessKey?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsSessionToken?: string;
}
