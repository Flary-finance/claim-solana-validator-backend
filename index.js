// server.mjs
import express from "express";
import cors from "cors";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { Wallet } from "ethers";
import { PORT, SOL_CLAIM_AUTHORITY_PRIVATE_KEY } from "./config.js";

const CONTRACT_ADDRESS = "0x690220542cC7fF0BA0f7A25FE81Cc1DDB8D34c7F";
const CHAIN_ID = 11155111;

const app = express();

// middlewares
app.use(cors());
app.use(express.json());

// POST /validate
app.post("/validate", async (req, res) => {
    const { message, signedMessage, solanaAddress } = req.body ?? {};

    if (!message || !signedMessage || !solanaAddress) {
        return res.status(400).json({
            error: "message, signedMessage and solanaAddress are required",
        });
    }

    let sigBytes = null;
    try {
        sigBytes = Buffer.from(signedMessage, "base64");
    } catch (e) {
        return res.status(400).json({ error: "signedMessage is not valid base64" });
    }
    if (sigBytes.length !== 64) {
        return res
            .status(400)
            .json({ error: `Ed25519 signature must be 64 bytes, got ${sigBytes.length}` });
    }

    let pubkeyBytes = null;
    try {
        pubkeyBytes = bs58.decode(solanaAddress);
    } catch (e) {
        return res.status(400).json({ error: "solanaAddress is not valid base58" });
    }
    if (pubkeyBytes.length !== 32) {
        return res
            .status(400)
            .json({ error: `Solana public key must be 32 bytes, got ${pubkeyBytes.length}` });
    }

    const messageBytes = new TextEncoder().encode(message);

    const ok = nacl.sign.detached.verify(
        messageBytes,
        new Uint8Array(sigBytes),
        new Uint8Array(pubkeyBytes)
    );

    if (!ok) {
        return res.status(401).json({ valid: false, error: "signature verification failed" });
    }

    const [deadlineStr, evmAddress] = message.split(":");
    const deadline = Number(deadlineStr);

    const domain = {
        name: "SolanaClaim",
        version: "1",
        chainId: CHAIN_ID,
        verifyingContract: CONTRACT_ADDRESS,
    };

    const types = {
        Proof: [
            { name: "solanaPubkey", type: "bytes32" },
            { name: "evmAddress", type: "address" },
            { name: "deadline", type: "uint64" },
        ],
    };

    const solanaPubkeyHex = ("0x" + Buffer.from(bs58.decode(solanaAddress)).toString("hex"));

    const proof = {
        solanaPubkey: solanaPubkeyHex,
        evmAddress,
        deadline: deadline,
    };

    const wallet = new Wallet(SOL_CLAIM_AUTHORITY_PRIVATE_KEY);
    const signature = await wallet.signTypedData(domain, types, proof);

    res.json({ signature });
});

app.listen(PORT, () => {
    console.log(`Backend listening on http://localhost:${PORT}`);
});
