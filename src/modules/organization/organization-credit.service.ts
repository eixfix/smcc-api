import {
  BadRequestException,
  Injectable,
  NotFoundException,
  HttpException,
  HttpStatus
} from '@nestjs/common';
import type { Prisma } from '@prisma/client';

import { PrismaService } from '../../prisma/prisma.service';
import {
  CREDIT_COST_SERVER_SCAN,
  CREDIT_COST_SERVER_TELEMETRY
} from '../../common/constants/credit-costs';

export class InsufficientCreditsException extends HttpException {
  constructor(required: number, context?: string) {
    super(
      context
        ? `Insufficient organization credits to ${context}. Required: ${required} credits.`
        : `Insufficient organization credits. Required: ${required} credits.`,
      HttpStatus.PAYMENT_REQUIRED
    );
  }
}

type PrismaClientLike = PrismaService | Prisma.TransactionClient;

@Injectable()
export class OrganizationCreditService {
  constructor(private readonly prisma: PrismaService) {}

  async spendCredits(
    organizationId: string,
    amount: number,
    tx?: Prisma.TransactionClient,
    context?: string
  ): Promise<void> {
    if (amount <= 0) {
      throw new BadRequestException('Credit amount must be greater than zero.');
    }
    if (!Number.isInteger(amount)) {
      throw new BadRequestException('Credit amount must be an integer.');
    }

    const client = this.resolveClient(tx);
    const organization = await client.organization.findUnique({
      where: { id: organizationId },
      select: { credits: true }
    });

    if (!organization) {
      throw new NotFoundException('Organization not found.');
    }

    if (organization.credits < amount) {
      throw new InsufficientCreditsException(amount, context);
    }

    const now = new Date();

    await client.organization.update({
      where: { id: organizationId },
      data: {
        credits: {
          decrement: amount
        },
        lastDebitAt: now
      }
    });
  }

  async addCredits(
    organizationId: string,
    amount: number,
    tx?: Prisma.TransactionClient
  ): Promise<number> {
    if (amount <= 0) {
      throw new BadRequestException('Credit amount must be greater than zero.');
    }
    if (!Number.isInteger(amount)) {
      throw new BadRequestException('Credit amount must be an integer.');
    }

    const client = this.resolveClient(tx);

    const now = new Date();

    const updated = await client.organization.update({
      where: { id: organizationId },
      data: {
        credits: {
          increment: amount
        },
        lastCreditedAt: now
      },
      select: { credits: true, scanSuspendedAt: true }
    });

    if (updated.credits > 0 && updated.scanSuspendedAt) {
      await client.organization.update({
        where: { id: organizationId },
        data: {
          scanSuspendedAt: null
        }
      });
    }

    return Number(updated.credits);
  }

  async refundCredits(
    organizationId: string,
    amount: number
  ): Promise<void> {
    await this.addCredits(organizationId, amount);
  }

  private resolveClient(tx?: Prisma.TransactionClient): PrismaClientLike {
    return tx ?? this.prisma;
  }

  async debitForServerScan(
    organizationId: string,
    tx?: Prisma.TransactionClient
  ): Promise<void> {
    await this.spendCredits(
      organizationId,
      CREDIT_COST_SERVER_SCAN,
      tx,
      'queue a server scan'
    );
  }

  async debitForTelemetry(
    organizationId: string,
    tx?: Prisma.TransactionClient
  ): Promise<void> {
    await this.spendCredits(
      organizationId,
      CREDIT_COST_SERVER_TELEMETRY,
      tx,
      'record server telemetry'
    );
  }
}
