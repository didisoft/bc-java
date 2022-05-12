package org.bouncycastle.bcpg;

import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.*;

import java.io.InputStream;
import java.io.IOException;

/**
 * Packet representing AEAD encrypted data
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-04#section-5.16
 * @author Atanas Krachev <atanas@didisoft.com>
 */
public class AeadEncryptedPacket extends InputStreamPacket //, PublicKeyAlgorithmTag
{
    private byte version;
    private byte algorithm;
    private byte mode;
    private byte chunkSizeBytes;
    private byte[] IV;
    private InputStream Payload;

    public static final byte MODE_EAX = 1;
    public static final byte MODE_OCB = 2;
    public static final byte MODE_GCM = 100;


    public AeadEncryptedPacket(BCPGInputStream bcpgIn) throws IOException 
    {
    	super(bcpgIn);
    	
        version = (byte)bcpgIn.read();
        if (version != 1) throw new IllegalArgumentException("Wrong AEAD packet version: " + version);

        algorithm = (byte)bcpgIn.read();
        mode = (byte)bcpgIn.read();
        chunkSizeBytes = (byte)bcpgIn.read();

        IV  = new byte[getIvLenght(mode)];
        bcpgIn.read(getIV(), 0, getIV().length);

        Payload = bcpgIn;
    }


    /**
     * AEAD Chunk size in Bytes
     * @return AEAD Chunk size in Bytes
     */
    public int getChunkSize()
    {
           return (int)Math.pow(2, (chunkSizeBytes + 6));
    }

    private int getIvLenght(byte mode)
    {
        switch (mode)
        {
            case MODE_EAX: return 16;
            case MODE_OCB: return 15;
            case MODE_GCM: return 12;
            default: throw new IllegalArgumentException("mode");
        }
    }

    public AEADBlockCipher createCipher()
    {
        switch (this.mode)
        {
            case MODE_EAX: return new EAXBlockCipher(new AESEngine());
            case MODE_OCB: return new OCBBlockCipher(new AESEngine(), new AESEngine());
            case MODE_GCM: return new GCMBlockCipher(new AESEngine());
            default: throw new IllegalArgumentException("mode");
        }
    }

    public byte[] getNonce(long chunkindex)
    {
        switch (this.mode)
        {
            case MODE_EAX:
                {
                    byte[] nonce = new byte[16];
                    int i = 8;
                    System.arraycopy(this.IV, 0, nonce, 0, nonce.length);
                    nonce[i++] ^= (byte)(chunkindex >> 56);
                    nonce[i++] ^= (byte)(chunkindex >> 48);
                    nonce[i++] ^= (byte)(chunkindex >> 40);
                    nonce[i++] ^= (byte)(chunkindex >> 32);
                    nonce[i++] ^= (byte)(chunkindex >> 24);
                    nonce[i++] ^= (byte)(chunkindex >> 16);
                    nonce[i++] ^= (byte)(chunkindex >> 8);
                    nonce[i++] ^= (byte)(chunkindex);
                    return nonce;
                }
            case MODE_OCB:
                {
                    byte[] nonce = new byte[15];
                    int i = 7;
                    System.arraycopy(this.IV, 0, nonce, 0, nonce.length);
                    nonce[i++] ^= (byte)(chunkindex >> 56);
                    nonce[i++] ^= (byte)(chunkindex >> 48);
                    nonce[i++] ^= (byte)(chunkindex >> 40);
                    nonce[i++] ^= (byte)(chunkindex >> 32);
                    nonce[i++] ^= (byte)(chunkindex >> 24);
                    nonce[i++] ^= (byte)(chunkindex >> 16);
                    nonce[i++] ^= (byte)(chunkindex >> 8);
                    nonce[i++] ^= (byte)(chunkindex);
                    return nonce;
                }
            case MODE_GCM:
                {
                    return this.IV;
                }
            default: throw new IllegalArgumentException();
        }
    }

    public byte getVersion() {
		return version;
	}

	public byte getAlgorithm() {
		return algorithm;
	}

	public byte getMode() {
		return mode;
	}

	public int getChunkSizeBytes() {
		return chunkSizeBytes;
	}

	public byte[] getIV() {
		return IV;
	}

	public InputStream getDataStream() {
		return Payload;
	}

	public int getTagLength()
    {
        switch (mode)
        {
            case MODE_EAX: return 16;
            case MODE_OCB: return 16;
            case MODE_GCM: return 16;
            default: throw new IllegalArgumentException();
        }
    }

}