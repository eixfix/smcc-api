import { PartialType } from '@nestjs/mapped-types';

import { CreateUptimeTargetDto } from './create-uptime-target.dto';

export class UpdateUptimeTargetDto extends PartialType(CreateUptimeTargetDto) {}
