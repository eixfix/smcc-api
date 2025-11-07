import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import type { Project } from '@prisma/client';
import { Role } from '@prisma/client';

import { CREDIT_COST_CREATE_PROJECT } from '../../common/constants/credit-costs';
import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import { OrganizationCreditService } from '../organization/organization-credit.service';

@Injectable()
export class ProjectService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly creditService: OrganizationCreditService
  ) {}

  async findAllByOrganization(
    organizationId: string,
    user: AuthenticatedUser
  ): Promise<Project[]> {
    await this.verifyOrganizationAccess(organizationId, user);

    return this.prisma.project.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' }
    });
  }

  async create(
    organizationId: string,
    payload: CreateProjectDto,
    user: AuthenticatedUser
  ): Promise<Project> {
    await this.verifyOrganizationAccess(organizationId, user);

    return this.prisma.$transaction(async (tx) => {
      await this.creditService.spendCredits(
        organizationId,
        CREDIT_COST_CREATE_PROJECT,
        tx,
        'create a project'
      );

      return tx.project.create({
        data: {
          name: payload.name,
          description: payload.description,
          organizationId
        }
      });
    });
  }

  async update(id: string, payload: UpdateProjectDto, user: AuthenticatedUser): Promise<Project> {
    const project = await this.prisma.project.findUnique({
      where: { id },
      select: { organizationId: true }
    });

    if (!project) {
      throw new NotFoundException('Project not found.');
    }

    await this.verifyOrganizationAccess(project.organizationId, user);

    return this.prisma.project.update({
      where: { id },
      data: payload
    });
  }

  private async verifyOrganizationAccess(
    organizationId: string,
    user: AuthenticatedUser
  ): Promise<void> {
    if (user.role === Role.ADMINISTRATOR) {
      const exists = await this.prisma.organization.findUnique({
        where: { id: organizationId },
        select: { id: true }
      });

      if (!exists) {
        throw new NotFoundException('Organization not found.');
      }

      return;
    }

    const membership = await this.prisma.organizationMember.findFirst({
      where: {
        organizationId,
        userId: user.userId
      },
      select: { id: true }
    });

    if (!membership) {
      const exists = await this.prisma.organization.findUnique({
        where: { id: organizationId },
        select: { id: true }
      });

      if (!exists) {
        throw new NotFoundException('Organization not found.');
      }

      throw new ForbiddenException('You do not have access to this organization.');
    }
  }
}
