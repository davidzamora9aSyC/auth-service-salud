import { IsIn, IsInt, IsString, Min } from 'class-validator';

export class UpdateDoctorOnboardingSettingsDto {
  @IsInt()
  @Min(1)
  inviteTrialDurationValue!: number;

  @IsString()
  @IsIn(['DAY', 'MONTH'])
  inviteTrialDurationUnit!: 'DAY' | 'MONTH';
}
