import { AppService } from './app.service';
export declare class AppController {
    private readonly appService;
    constructor(appService: AppService);
    getRoot(): {
        status: string;
    };
    getHealth(): {
        status: string;
        timestamp: string;
    };
}
//# sourceMappingURL=app.controller.d.ts.map