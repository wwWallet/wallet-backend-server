import { AppTokenUser } from "../middlewares/auth.middleware";

// to make the file a module and avoid the TypeScript error
export {}

declare global {
  namespace Express {
    export interface Request {
      user?: AppTokenUser;
    }
  }
}
