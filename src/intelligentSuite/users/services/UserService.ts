/* eslint-disable @typescript-eslint/no-empty-function */
import {Service} from "typedi";
import zxcvbn from "zxcvbn";
import {BadRequestError} from "../../../common/errors/BadRequestError";
import {ErrorMsg} from "../../../common/errors/ErrorCode";
import {InvitationService} from "../../invitations/services/InvitationService";
import {User} from "../entities/User";
import {SignUpInput, UserProfileInput} from "../input/UserInput";
import {UserRepository} from "../repositories/UserRepository";

@Service()
export class UserService {
    constructor(
        private readonly userRepository: UserRepository,
        private readonly invitationService: InvitationService,
    ) {}

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async signUp(input: SignUpInput, invitationCode: string): Promise<User> {
        // const invitation = await this.invitationService.getInvitationByCode(invitationCode);
        // if (!invitation) {
        //     throw new BadRequestError(ErrorMsg.INVITATION_CODE_NOT_FOUND);
        // }
        // invitation.verifyInvitation(input.email);

        const existingUser = await this.userRepository.getByEmail(input.email);
        if (existingUser) {
            throw new BadRequestError(ErrorMsg.EMAIL_ALREADY_IN_USE);
        }

        this.validateUserPassword(input.password);

        const user = User.createUser({
            name: input.name,
            email: input.email,
            businessAccount: {
                businessName: "test",
                users: [],
                isDeleted: () => false,
                update: () => {},
                id: "01H4616SGMFZ1GX71ZG5DCZMFD",
                createdAt: new Date(),
                setId: () => {},
                updatedAt: new Date(),
            }, //invitation.businessAccount,
            password: input.password,
            isAdmin: true, //invitation.isAdmin,
        });
        await this.userRepository.save(user);
        // await this.invitationService.useInvitation(invitation, user);
        return user;
    }

    async updateProfile(user: User, input: UserProfileInput): Promise<User> {
        if (input.newPassword && !user.verifyPassword(input.currentPassword)) {
            throw new BadRequestError(ErrorMsg.PASSWORD_DO_NOT_MATCH);
        }

        if (input.newPassword) {
            this.validateUserPassword(input.newPassword);
        }
        user.updateProfile(input);
        return this.userRepository.save(user);
    }

    async acceptTermsAndConditions(user: User): Promise<void> {
        user.acceptTermsAndConditions();
        await this.userRepository.save(user);
    }

    async deleteMe(inputUser: User) {
        await this.userRepository.delete(inputUser);
    }

    private validateUserPassword(password: string) {
        if (password.length < 8) {
            throw new BadRequestError(ErrorMsg.PASSWORD_LENGTH_ERROR);
        }

        const passwordStrength = zxcvbn(password);

        if (password && passwordStrength.score < 3) {
            throw new BadRequestError(ErrorMsg.PASSWORD_TOO_WEAK);
        }
    }
}
