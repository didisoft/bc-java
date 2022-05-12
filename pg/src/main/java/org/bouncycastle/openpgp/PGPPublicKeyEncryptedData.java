package org.bouncycastle.openpgp;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.AeadEncryptedPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * A public key encrypted data object.
 */
public class PGPPublicKeyEncryptedData
    extends PGPEncryptedData
{
    PublicKeyEncSessionPacket keyData;

    PGPPublicKeyEncryptedData(
        PublicKeyEncSessionPacket keyData,
        InputStreamPacket encData)
    {
        super(encData);

        this.keyData = keyData;
    }

    private boolean confirmCheckSum(
        byte[] sessionInfo)
    {
        int check = 0;

        for (int i = 1; i != sessionInfo.length - 2; i++)
        {
            check += sessionInfo[i] & 0xff;
        }

        return (sessionInfo[sessionInfo.length - 2] == (byte)(check >> 8))
            && (sessionInfo[sessionInfo.length - 1] == (byte)(check));
    }

    /**
     * Return the keyID for the key used to encrypt the data.
     *
     * @return long
     */
    public long getKeyID()
    {
        return keyData.getKeyID();
    }

    /**
     * Return the symmetric key algorithm required to decrypt the data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data.
     * @return the identifier of the {@link SymmetricKeyAlgorithmTags encryption algorithm} used to
     * encrypt this object.
     * @throws PGPException if the session data cannot be recovered.
     */
    public int getSymmetricAlgorithm(
        PublicKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        byte[] plain = dataDecryptorFactory.recoverSessionData(keyData.getAlgorithm(), keyData.getEncSessionKey());

        return plain[0];
    }

    /**
     * Return the symmetric session key required to decrypt the data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data.
     * @return session key used to decrypt the data protected by this object
     * @throws PGPException if the session data cannot be recovered.
     */
    public PGPSessionKey getSessionKey(
        PublicKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getAlgorithm(), keyData.getEncSessionKey());
        if (!confirmCheckSum(sessionData))
        {
            throw new PGPKeyValidationException("key checksum failed");
        }

        return new PGPSessionKey(sessionData[0] & 0xff, Arrays.copyOfRange(sessionData, 1, sessionData.length - 2));
    }

    /**
     * Open an input stream which will provide the decrypted data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data and provide the stream.
     * @return the resulting input stream
     * @throws PGPException if the session data cannot be recovered or the stream cannot be created.
     */
    public InputStream getDataStream(
        PublicKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        return getDataStream(dataDecryptorFactory, getSessionKey(dataDecryptorFactory));
    }

    public InputStream getDataStream(
        SessionKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        return getDataStream(dataDecryptorFactory, dataDecryptorFactory.getSessionKey());
    }

    private InputStream decryptAead(PGPSessionKey sessionKey, AeadEncryptedPacket packet)
    {
        encStream = new BCPGInputStream(
                new AeadCipherStream(false, 
                                    packet.getDataStream(), 
                                    new KeyParameter(sessionKey.getKey(), 0, sessionKey.getKey().length),
                                    packet));

        return encStream;
    }
    
    private class AeadCipherStream extends InputStream
    {
        private boolean forEncryption;
        private InputStream stream;
        private AEADBlockCipher inCipher;
        private byte[] mInBuf;
        private int mInPos;            
        private boolean inStreamEnded;
        private KeyParameter key;
        private AeadEncryptedPacket packet;
        private long chunkIndex;
        private long bytesProcessed;

        public AeadCipherStream(
                    boolean forEncryption,
                    InputStream stream,
                    KeyParameter key,
                    AeadEncryptedPacket packet)
        {
            this.forEncryption = forEncryption;
            this.stream = stream;
            this.key = key;
            this.packet = packet;
            this.chunkIndex = 0;
            this.bytesProcessed = 0;

            inCipher = packet.createCipher();
            mInBuf = null;
        }

        public int read() throws java.io.IOException
        {
            if (inCipher == null)
                return stream.read();

            if (mInBuf == null || mInPos >= mInBuf.length)
            {
            	try {
                    if (!fillInBuf())
                        return -1;
            	} catch (InvalidCipherTextException e) {
            		throw new IOException(e);
            	}
            }

            return (int)(mInBuf[mInPos++] & 0xff);
        }

        public int read(
            byte[] buffer,
            int offset,
            int count) throws IOException
        {
            int num = 0;
            while (num < count)
            {
                if (mInBuf == null || mInPos >= mInBuf.length)
                {
                	try {
                		if (!fillInBuf())
                			break;
                	} catch (InvalidCipherTextException e) {
                		throw new IOException(e);
                	}
                }

                int numToCopy = Math.min(count - num, mInBuf.length - mInPos);
                System.arraycopy(mInBuf, mInPos, buffer, offset + num, numToCopy);
                mInPos += numToCopy;
                num += numToCopy;
            }

            return num;
        }

        private boolean fillInBuf() throws IOException, InvalidCipherTextException
        {
            if (inStreamEnded)
                return false;

            mInPos = 0;
            do
            {
                mInBuf = readAndProcessBlock();
            }
            while (!inStreamEnded && mInBuf == null);

            return mInBuf != null;
        }

        private byte[] readAndProcessBlock() throws IOException, InvalidCipherTextException
        {
            byte[] adata = { (byte)(0xC0 | 20), packet.getVersion(), (byte)packet.getAlgorithm(), (byte)packet.getMode(), (byte)packet.getChunkSizeBytes(),
                (byte)((chunkIndex >> 56) & 0xFF),
                (byte)((chunkIndex >> 48) & 0xFF),
                (byte)((chunkIndex >> 40) & 0xFF),
                (byte)((chunkIndex >> 32) & 0xFF),
                (byte)((chunkIndex >> 24) & 0xFF),
                (byte)((chunkIndex >> 16) & 0xFF),
                (byte)((chunkIndex >> 8) & 0xFF),
                (byte)(chunkIndex & 0xFF)};

            this.inCipher = packet.createCipher();
            AEADParameters parameters = new AEADParameters(key,
                                                packet.getTagLength() * 8,
                                                packet.getNonce(this.chunkIndex), adata);
            inCipher.init(this.forEncryption, parameters);

            int tagLenIfDecrypting = (this.forEncryption ? 0 : this.packet.getTagLength());
            int tagLenIfEncrypting = (this.forEncryption ? this.packet.getTagLength() : 0);
                        
            int readSize = packet.getChunkSize() + tagLenIfDecrypting;
            byte[] block = new byte[readSize];
            int numRead = 0;
            do
            {
                int count = stream.read(block, numRead, block.length - numRead);
                if (count < 1)
                {
                    inStreamEnded = true;
                    break;
                }
                numRead += count;
            }
            while (numRead < block.length);

            this.bytesProcessed += numRead - tagLenIfDecrypting;

            byte[] bytes = null;
            if (packet.getChunkSize() > numRead)
            {
                    byte[] lastBlock = new byte[numRead - tagLenIfDecrypting];
                    System.arraycopy(block, 0, lastBlock, 0, numRead - tagLenIfDecrypting);
                    
                    bytes = new byte[lastBlock.length + tagLenIfEncrypting - tagLenIfDecrypting];
                    inCipher.processBytes(lastBlock, 0, lastBlock.length, bytes, 0);
                    inCipher.doFinal(bytes, 0);

                    // Final Tail tag
                    this.chunkIndex++;
                    this.bytesProcessed -= tagLenIfDecrypting;

                    byte[] adataLast = 
                     { (byte)(0xC0 | 20), packet.getVersion(), (byte)packet.getAlgorithm(), (byte)packet.getMode(), (byte)packet.getChunkSizeBytes(),
                        (byte)((chunkIndex >> 56) & 0xFF),
                        (byte)((chunkIndex >> 48) & 0xFF),
                        (byte)((chunkIndex >> 40) & 0xFF),
                        (byte)((chunkIndex >> 32) & 0xFF),
                        (byte)((chunkIndex >> 24) & 0xFF),
                        (byte)((chunkIndex >> 16) & 0xFF),
                        (byte)((chunkIndex >> 8) & 0xFF),
                        (byte)(chunkIndex & 0xFF),
                        (byte)((this.bytesProcessed >> 56)& 0xFF),
                        (byte)((bytesProcessed >> 48)& 0xFF),
                        (byte)((bytesProcessed >> 40)& 0xFF),
                        (byte)((bytesProcessed >> 32)& 0xFF),
                        (byte)((bytesProcessed >> 24)& 0xFF),
                        (byte)((bytesProcessed >> 16)& 0xFF),
                        (byte)((bytesProcessed >> 8)& 0xFF),
                        (byte)(bytesProcessed& 0xFF) };

                    this.inCipher = packet.createCipher();
                    parameters = new AEADParameters(key,
                                                        packet.getTagLength() * 8,
                                                        packet.getNonce(this.chunkIndex), adataLast);
                    inCipher.init(this.forEncryption, parameters);

                    byte[] tail = new byte[tagLenIfDecrypting];
                    System.arraycopy(block, lastBlock.length, tail, 0, tail.length);
                    byte[] tailProcessed = new byte[tail.length];
                    inCipher.processBytes(tail, 0, tail.length, tailProcessed, 0);
                    inCipher.doFinal(tailProcessed, 0);

                    if (this.forEncryption)
                    {
                    	bytes = Arrays.concatenate(bytes, tailProcessed);
                    }
            }
            else
            {
                bytes = new byte[numRead + tagLenIfEncrypting - tagLenIfDecrypting];
            	
                inCipher.processBytes(block, 0, numRead, bytes, 0);
                inCipher.doFinal(bytes, 0);
            }

            if (bytes != null && bytes.length == 0)
            {
                bytes = null;
            }

            this.chunkIndex++;
            return bytes;
        }

        public void close() throws IOException
        {
        	stream.close();
        }
    }
    
    /**
     * Open an input stream which will provide the decrypted data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data and provide the stream.
     * @param sessionKey           the session key for the stream.
     * @return the resulting input stream
     * @throws PGPException if the session data cannot be recovered or the stream cannot be created.
     */
    private InputStream getDataStream(
        PGPDataDecryptorFactory dataDecryptorFactory,
        PGPSessionKey sessionKey)
        throws PGPException
    {
        if (sessionKey.getAlgorithm() != SymmetricKeyAlgorithmTags.NULL)
        {
            try
            {
            	if (encData instanceof AeadEncryptedPacket)
            		return decryptAead(sessionKey, (AeadEncryptedPacket)encData );
            	
                boolean withIntegrityPacket = encData instanceof SymmetricEncIntegrityPacket;

                PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(withIntegrityPacket, sessionKey.getAlgorithm(), sessionKey.getKey());

                BCPGInputStream encIn = encData.getInputStream();

                encStream = new BCPGInputStream(dataDecryptor.getInputStream(encIn));

                if (withIntegrityPacket)
                {
                    truncStream = new TruncatedStream(encStream);

                    integrityCalculator = dataDecryptor.getIntegrityCalculator();

                    encStream = new TeeInputStream(truncStream, integrityCalculator.getOutputStream());
                }

                byte[] iv = new byte[dataDecryptor.getBlockSize()];

                for (int i = 0; i != iv.length; i++)
                {
                    int ch = encStream.read();

                    if (ch < 0)
                    {
                        throw new EOFException("unexpected end of stream.");
                    }

                    iv[i] = (byte)ch;
                }

                int v1 = encStream.read();
                int v2 = encStream.read();

                if (v1 < 0 || v2 < 0)
                {
                    throw new EOFException("unexpected end of stream.");
                }

                //
                // some versions of PGP appear to produce 0 for the extra
                // bytes rather than repeating the two previous bytes
                //
                /*
                 * Commented out in the light of the oracle attack.
                if (iv[iv.length - 2] != (byte)v1 && v1 != 0)
                {
                    throw new PGPDataValidationException("data check failed.");
                }

                if (iv[iv.length - 1] != (byte)v2 && v2 != 0)
                {
                    throw new PGPDataValidationException("data check failed.");
                }
                */

                return encStream;
            }
            catch (PGPException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PGPException("Exception starting decryption", e);
            }
        }
        else
        {
            return encData.getInputStream();
        }
    }

    public int getAlgorithm()
    {
        return keyData.getAlgorithm();
    }

    public int getVersion()
    {
        return keyData.getVersion();
    }
}
