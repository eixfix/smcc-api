import { Controller, Get } from '@nestjs/common';

import { AppService } from './app.service';
import { Public } from '../../common/decorators/public.decorator';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Public()
  @Get('/')
  getRoot(): { status: string } {
    return this.appService.getStatus();
  }

  @Public()
  @Get('/health')
  getHealth(): { status: string; timestamp: string } {
    return this.appService.getDetailedStatus();
  }
}
