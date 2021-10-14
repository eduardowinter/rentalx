import { Router } from "express";

import { AuthenticateUserController } from "../modules/accounts/useCases/authenticateUser/AuthenticateUserController";

const authenticateRoutes = Router();

const authenticateUsersController = new AuthenticateUserController();

authenticateRoutes.post("/sessions", authenticateUsersController.handle);

export { authenticateRoutes };
