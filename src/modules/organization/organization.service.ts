import { ForbiddenException, Injectable } from '@nestjs/common';
import type { Organization } from '@prisma/client';
import { Role } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateOrganizationDto } from './dto/create-organization.dto';
import { UpdateOrganizationDto } from './dto/update-organization.dto';
import { OrganizationCreditService } from './organization-credit.service';

@Injectable()
export class OrganizationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly creditService: OrganizationCreditService
  ) {}

  findAll(user: AuthenticatedUser): Promise<(Organization & { _count: { projects: number } })[]> {
    const where =
      user.role === Role.ADMINISTRATOR
        ? {}
        : {
            members: {
              some: {
                userId: user.userId
              }
            }
          };

    return this.prisma.organization.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      include: {
        _count: {
          select: {
            projects: true
          }
        }
      }
    });
  }

  async findOne(id: string, user: AuthenticatedUser): Promise<Organization | null> {
    const organization = await this.prisma.organization.findUnique({ where: { id } });

    if (!organization) {
      return null;
    }

    if (user.role === Role.ADMINISTRATOR) {
      return organization;
    }

    const membership = await this.prisma.organizationMember.findFirst({
      where: {
        organizationId: id,
        userId: user.userId
      }
    });

    if (!membership) {
      throw new ForbiddenException('You do not have access to this organization.');
    }

    return organization;
  }

  async create(
    payload: CreateOrganizationDto
  ): Promise<
    Organization & {
      owner: { id: string; name: string; email: string; role: Role } | null;
      _count: { projects: number };
    }
  > {
    const passwordHash = await bcrypt.hash(payload.owner.password, 10);

    return this.prisma.$transaction(async (tx) => {
      const owner = await tx.user.create({
        data: {
          email: payload.owner.email,
          name: payload.owner.name,
          passwordHash,
          role: Role.OWNER
        },
        select: {
          id: true,
          name: true,
          email: true,
          role: true
        }
      });

      const organization = await tx.organization.create({
        data: {
          name: payload.name,
          slug: payload.slug,
          ownerId: owner.id,
          members: {
            create: {
              userId: owner.id,
              role: Role.OWNER
            }
          }
        },
        include: {
          owner: {
            select: {
              id: true,
              name: true,
              email: true,
              role: true
            }
          },
          _count: {
            select: {
              projects: true
            }
          }
        }
      });

      return organization;
    });
  }

  update(id: string, payload: UpdateOrganizationDto): Promise<Organization> {
    return this.prisma.organization.update({
      where: { id },
      data: payload
    });
  }

  async addCredits(id: string, amount: number): Promise<{ credits: number }> {
    const credits = await this.creditService.addCredits(id, amount);
    return { credits };
  }
}
