"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CreateOrganizationDto = exports.CreateOrganizationOwnerDto = void 0;
const class_transformer_1 = require("class-transformer");
const class_validator_1 = require("class-validator");
class CreateOrganizationOwnerDto {
}
exports.CreateOrganizationOwnerDto = CreateOrganizationOwnerDto;
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.Length)(3, 60),
    __metadata("design:type", String)
], CreateOrganizationOwnerDto.prototype, "name", void 0);
__decorate([
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], CreateOrganizationOwnerDto.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(8),
    __metadata("design:type", String)
], CreateOrganizationOwnerDto.prototype, "password", void 0);
class CreateOrganizationDto {
}
exports.CreateOrganizationDto = CreateOrganizationDto;
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.Length)(3, 60),
    __metadata("design:type", String)
], CreateOrganizationDto.prototype, "name", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.Matches)(/^[a-z0-9-]+$/, {
        message: 'Slug can only include lowercase letters, numbers, and hyphens.'
    }),
    __metadata("design:type", String)
], CreateOrganizationDto.prototype, "slug", void 0);
__decorate([
    (0, class_validator_1.ValidateNested)(),
    (0, class_transformer_1.Type)(() => CreateOrganizationOwnerDto),
    __metadata("design:type", CreateOrganizationOwnerDto)
], CreateOrganizationDto.prototype, "owner", void 0);
//# sourceMappingURL=create-organization.dto.js.map