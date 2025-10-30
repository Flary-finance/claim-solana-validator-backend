import { config } from "dotenv";

config();

const getEnv = (name) => {
    const res = process.env[name];
    if (!res) {
        throw new Error(`env ${name} not found`);
    }

    return res;
};

export const PORT = getEnv('PORT');
export const SOL_CLAIM_AUTHORITY_PRIVATE_KEY = getEnv("SOL_CLAIM_AUTHORITY_PRIVATE_KEY");