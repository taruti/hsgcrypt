module Codec.LibGCrypt.Low where

-- Interface to libgcrypt
{#context lib="gcrypt" prefix="gcry" #}
#include <gcrypt.h>

import Control.Concurrent.MVar
import Control.Monad
import Data.ByteString as BS
import Data.ByteString.Internal
import Data.ByteString.Unsafe
import Foreign
import Foreign.C
import Foreign.Concurrent as FC
import Numeric(showHex)

-- Many things are done via the control functions + macros. Wrap it.
{#enum ctl_cmds as ControlCommand {underscoreToCase} deriving(Show) #}

-- Errors

newtype Err = Err { ue :: {#type gcry_error_t#} }

instance Show Err where
--    show err@(Err num) = unwords ["gcrypt error",show num,":",gcry_strerror err,"at", gcry_strsource err]
    show = errMsg

{-# NOINLINE errLock #-}
errLock :: MVar ()
errLock = unsafePerformIO $ newMVar ()

errMsg (Err num) = unsafePerformIO $ withMVar errLock $ \_ -> do
  emsg <- peekCString =<< {#call unsafe gcry_strerror #} num
  eloc <- peekCString =<< {#call unsafe gcry_strsource #} num
  return $ Prelude.concat ["gcrypt error ",show num,": ",emsg," at ", eloc]

-- {#fun unsafe gcry_strsource {ue `Err'} -> `String' #}
-- {#fun unsafe gcry_strerror  {ue `Err'} -> `String' #}

-- Type definitions
{#pointer sexp_t as SExp foreign newtype #}


-- Handlers <omitted>

{-
init_gcrypt :: IO ()
init_gcrypt = do
  gcry_check_version nullPtr
  gcry_control_I3 (e2ci CtlInitSecmem) 16384 0
  gcry_control_I2 (e2ci CtlInitializationFinished) 0

foreign import ccall unsafe gcry_check_version :: Ptr CChar -> IO (Ptr CChar)
foreign import ccall unsafe "gcry_control" gcry_control_I3 :: CInt -> CInt -> CInt -> IO ()
foreign import ccall unsafe "gcry_control" gcry_control_I2 :: CInt -> CInt -> IO ()
-}

-- | May be called multiple times without any harm.
foreign import ccall safe "hsgcrypt_wrap_gcrypt_init" init_gcrypt :: IO ()

-- Symmetric cryptography

{#enum cipher_algos as CipherAlgo {underscoreToCase} deriving(Show) #}
{#enum cipher_modes as CipherMode {underscoreToCase} deriving(Show) #}
{#enum cipher_flags as CipherFlag {underscoreToCase} deriving(Show) #}

{#pointer cipher_hd_t as CH foreign newtype #}

foreign import ccall unsafe gcry_cipher_close :: Ptr a -> IO ()

{#fun unsafe cipher_open {alloca- `CH' pch*, e2ci `CipherAlgo', e2ci `CipherMode', e2cu `Int'} -> `()' eh*- #}
{#fun unsafe cipher_ctl  {ch* `CH', e2ci `ControlCommand', wBuf* `ByteString'&} -> `()' eh*- #}

cipher_setkey h  = cipher_ctl h CtlSetKey
cipher_setiv  h  = cipher_ctl h CtlSetIv
cipher_setctr  h = cipher_ctl h CtlSetCtr
cipher_reset   h = cipher_ctl h CtlReset BS.empty

{#fun unsafe cipher_encrypt as cipher_encrypt_raw {ch* `CH', castPtr `Ptr a', `Int', castPtr `Ptr a', `Int'} -> `()' eh*- #}
{#fun unsafe cipher_decrypt as cipher_decrypt_raw {ch* `CH', castPtr `Ptr a', `Int', castPtr `Ptr a', `Int'} -> `()' eh*- #}

cipher_sync h = cipher_ctl h CtlCfbSync BS.empty

-- Hashing - i.e. message digests

{#enum md_algos as MdAlgo {underscoreToCase} deriving(Show) #}
{#enum md_flags as MdFlag {underscoreToCase} deriving(Show) #}

{#pointer md_hd_t as MDH foreign newtype #}

foreign import ccall unsafe gcry_md_close :: Ptr a -> IO ()

{#fun unsafe md_open {alloca- `MDH' pmdh*, e2ci `MdAlgo', e2cu `Int'} -> `()' eh*- #}

{#fun unsafe md_enable {mdh* `MDH', e2ci `MdAlgo'} -> `()' eh*- #}
{#fun unsafe md_setkey {mdh* `MDH', wBuf* `ByteString'& } -> `()' eh*- #}
{#fun unsafe md_reset {mdh* `MDH'} -> `()' #}
{#fun unsafe md_write {mdh* `MDH', wBuf* `ByteString'& } -> `()' #}

-- {#fun unsafe md_ctl {id `MDH', e2ci `ControlCommand', wBuf* `ByteString'&} -> `()' eh*- #}
-- not needed - md_read does this.
-- md_final h = md_ctl h CtlFinalize BS.empty

md_read :: MDH -> MdAlgo -> IO ByteString
md_read m algo = do
  len <- {#call unsafe md_get_algo_dlen #} (e2ci algo)
  cp <-  mdh m $ \mp -> {#call md_read#} mp  (e2ci algo)
  when (cp == nullPtr) $ fail "md_read: Wrong hash algorithm"
  packCStringLen (castPtr cp,fromIntegral len)

md_hash_buffer :: MdAlgo -> ByteString -> IO ByteString
md_hash_buffer algo bs = do
  len <- {#call unsafe md_get_algo_dlen #} $ e2ci algo
  create (fromIntegral len) $ \ptr -> wBuf bs (uncurry ({#call unsafe md_hash_buffer #} (e2ci algo) (castPtr ptr)))

-- Public keys based on s-exps <omitted>

{#fun pk_genkey {alloca- `SExp' psexp*, sexp* `SExp'} -> `()' eh*- #}
{#fun pk_encrypt {alloca- `SExp' psexp*, sexp* `SExp', sexp* `SExp'} -> `()' eh*- #}
{#fun pk_decrypt {alloca- `SExp' psexp*, sexp* `SExp', sexp* `SExp'} -> `()' eh*- #}
{#fun pk_sign    {alloca- `SExp' psexp*, sexp* `SExp', sexp* `SExp'} -> `()' eh*- #}
{#fun pk_verify  {sexp* `SExp', sexp* `SExp', sexp* `SExp'} -> `()' eh*- #}


-- Public keys <Commented out - use sexps>

{-

{#enum ac_id_t as AcAlgo {underscoreToCase} deriving(Show) #}
type ACD = {#type gcry_ac_data_t #}
{#fun unsafe ac_data_new {id `Ptr ACD'} -> `()' eh*- #}
{#fun unsafe ac_data_destroy {id `ACD'} -> `()' #}
-- FIXME flags! (GCRY_AC_FLAG_DEALLOC, ...)
{#fun unsafe ac_data_set {id `ACD', `Int', `String', wmq* `MQ a'} -> `()' eh*- #}
{#fun unsafe ac_data_copy {id `Ptr ACD', id `ACD'} -> `()' eh*- #}
{#fun unsafe ac_data_length {id `ACD'} -> `Int' fromIntegral #}
-- FIXME flags! (GCRY_AC_FLAG_DEALLOC, ...)
{#fun unsafe ac_data_get_name  {id `ACD', `Int', `String', id `Ptr MPI'} -> `()' eh*- #}
{#fun unsafe ac_data_get_index {id `ACD', `Int', `Int', id `Ptr (Ptr CChar)', id `Ptr MPI'} -> `()' eh*- #}
{#fun unsafe ac_data_clear {id `ACD'} -> `()' #}

type ACH = {#type ac_handle_t #}
{#fun unsafe ac_open {id `Ptr ACH', e2ci `AcAlgo', wZero - `Int'} -> `()' eh*- #}
{#fun unsafe ac_close {id `ACH'} -> `()' #}

{#enum gcry_ac_key_type_t as AcKeyType {underscoreToCase} deriving(Show) #}

type AcKey     = {#type ac_key_t#}
type AcKeyPair = {#type ac_key_pair_t#}

{#fun unsafe ac_key_init {id `Ptr AcKey', id `ACH', e2ci `AcKeyType', id `ACD'} -> `()' eh*- #}

-- this might be Slow
{#fun ac_key_pair_generate as ac_key_pair_generate' {id `ACD', `Int',id `Ptr ()', id `Ptr AcKeyPair', castPtr `Ptr ()'} -> `()' eh*- #}

ac_key_pair_generate acd size pair = ac_key_pair_generate' acd size nullPtr pair nullPtr
ac_key_pair_generate_with_rsa_e acd size pair e =
  allocaBytes {#sizeof gcry_ac_key_spec_rsa_t#} $ \ptr -> do
    {#set gcry_ac_key_spec_rsa_t.e #} ptr e
    ac_key_pair_generate' acd size (castPtr ptr) pair nullPtr

{#fun unsafe ac_key_pair_extract {id `AcKeyPair', e2ci `AcKeyType'} -> `AcKey' id #}
{#fun unsafe ac_key_destroy {id `AcKey' } -> `()' #}
{#fun unsafe ac_key_pair_destroy {id `AcKeyPair' } -> `()' #}
{#fun unsafe ac_key_data_get {id `AcKey'} -> `ACD' id #}

{#fun unsafe ac_key_test {id `ACH', id `AcKey'} -> `()' eh*- #}
{#fun unsafe ac_key_get_grip {id `ACH', id `AcKey', castPtr `Ptr ()'} -> `()' eh*- #}


-- these might be slow
{#fun ac_data_encrypt {id `ACH', wZero- `Int', id `AcKey', wmq* `MQ a', id `Ptr ACD'} -> `()' eh*- #}
{#fun ac_data_decrypt {id `ACH', wZero- `Int', id `AcKey', alloca- `MQ a' pmq*, id `ACD'} -> `()' eh*- #}
{#fun ac_data_sign {id `ACH', id `AcKey', wmq* `MQ a', id `Ptr ACD'} -> `()' eh*- #}
{#fun ac_data_verify {id `ACH', id `AcKey', wmq* `MQ a', id `ACD'} -> `()' eh*- #}
-}

-- Random numbers

{#enum random_level as RandomLevel {underscoreToCase} deriving(Show) #}

{#fun randomize {castPtr `Ptr a', `Int', e2ci `RandomLevel'} -> `()' #}


{-
Function: void * gcry_random_bytes (size_t nbytes, enum gcry_random_level level)

    Allocate a memory block consisting of nbytes fresh random bytes using a random quality as defined by level. 

Function: void * gcry_random_bytes_secure (size_t nbytes, enum gcry_random_level level)

    Allocate a memory block consisting of nbytes fresh random bytes using a random quality as defined by level. This function differs from gcry_random_bytes in that the returned buffer is allocated in a "secure" area of the memory. 
-}

{#fun create_nonce {id `Ptr ()', `Int'} -> `()' #}

-- S-Exps - as ForeignPtrs

foreign import ccall unsafe gcry_sexp_release :: Ptr a -> IO ()
-- {#fun unsafe sexp_release { `SExp'} -> `()' #}

{#fun unsafe sexp_nth_data as sexp_nth_data' {castPtr `Ptr ()', e2ci `Int', alloca- `Int' pci*} -> `Ptr CChar' id #}

sexp_nth_data :: SExp -> Int -> IO ByteString
sexp_nth_data sex idx = sexp sex (\ptr -> packCStringLen =<< sexp_nth_data' (castPtr ptr) idx)


{#fun unsafe sexp_nth_mpi  {sexp* `SExp', e2ci `Int', e2ci `MpiFormat'} -> `MQ a' pdmq* #}
{#enum sexp_format as SExpFormat {underscoreToCase} deriving(Show) #}
-- SECURITY BUG in libgcypt: passing integers here is unsafe! So just MPIs for now...
{#fun unsafe sexp_build_array {alloca- `SExp' psexp*, wNull- `Ptr CUInt', `String', id `Ptr (Ptr ())'} -> `()' eh*- #}

{#fun unsafe sexp_sprint as sexp_sprint' {sexp* `SExp', e2ci `SExpFormat', castPtr `Ptr a', e2cu `Int'} -> `Int' cu2i #}
sexp_sprint :: SExp -> SExpFormat -> Int -> IO ByteString
sexp_sprint sexp fmt max_len = createAndTrim max_len $ \ptr -> sexp_sprint' sexp fmt ptr max_len
{#fun unsafe sexp_find_token {sexp* `SExp', `String'&} -> `SExp' pdsexp* #}

foreign import ccall unsafe "gcry_sexp_build" sexp_build1B' :: Ptr (Ptr ()) -> Ptr CSize -> Ptr CChar -> CSize -> Ptr CChar -> IO CUInt

sexp_build1B :: String -> ByteString -> IO SExp
sexp_build1B fmt bs = do
  withCString fmt $ \cfmt    -> do
  alloca          $ \sep     -> do
  wBuf bs         $ \(bp,bl) -> do
  eh =<< sexp_build1B' sep nullPtr cfmt (fromIntegral bl) bp -- Is it CSize or CInt?!
  psexp sep

st k = ps =<< sexp_build_array k nullPtr
ps s = BS.putStrLn =<< sexp_sprint s SexpFmtDefault 4096




-- MPI library (bignums)

{#pointer mpi_t as MPI_Raw foreign #}
-- type MPI = {#type gcry_mpi_t#}
data Secure = Secure
data Normal = Normal
newtype MQ s = MQ { umq :: MPI_Raw }

foreign import ccall unsafe gcry_mpi_release :: Ptr a -> IO ()

{#fun mpi_new  {`Int'} -> `MQ Normal' pdmq* #}
{#fun mpi_snew {`Int'} -> `MQ Secure' pdmq* #}
{#fun mpi_copy {wmq* `MQ a'} -> `MQ a' pdmq* #}
{#fun mpi_set {wmq* `MQ a', wmq* `MQ a'} -> `MQ a' pdmq* #}
{#fun mpi_set_ui {wmq* `MQ a', fromIntegral `Int'} -> `MQ a' pdmq* #}
{#fun mpi_swap {wmq* `MQ a', wmq* `MQ a' } -> `()' #}
{#enum mpi_format as MpiFormat {underscoreToCase} deriving(Show) #}
{#fun mpi_scan {alloca- `MQ a' pmq*, e2ci `MpiFormat', wBuf* `ByteString'&, id `Ptr CUInt'} -> `()' eh*- #}
{#fun mpi_print {e2ci `MpiFormat', castPtr `Ptr Word8', `Int', id `Ptr CUInt', wmq* `MQ a' } -> `()' eh*- #}

-- Math functions omitted

{#fun mpi_cmp {wmq* `MQ a', wmq* `MQ b'} -> `Ordering' i2o #}

-- Most bit manipulations omitted

{#fun mpi_get_nbits {wmq* `MQ a' } -> `Int' fromIntegral #}

-- marshalling utilities

ch (CH fp) c = withForeignPtr fp c
pch :: Ptr a -> IO CH
pch ptr = peek (castPtr ptr) >>= (\rp -> liftM CH $ FC.newForeignPtr rp $ gcry_cipher_close rp)

mdh (MDH fp) c = withForeignPtr fp c
pmdh :: Ptr a -> IO MDH
pmdh ptr = peek (castPtr ptr) >>= (\rp -> liftM MDH $ FC.newForeignPtr rp $ gcry_md_close rp)


sexp (SExp fp) c = withForeignPtr fp c

pmq :: Ptr a -> IO (MQ b)
pmq ptr = pdmq =<< peek (castPtr ptr)

pdmq rp = fmap MQ $ FC.newForeignPtr rp $ gcry_mpi_release rp

psexp :: Ptr a -> IO SExp
psexp ptr = do
  se <- peek (castPtr ptr)
  liftM SExp $ FC.newForeignPtr se $ gcry_sexp_release se

pdsexp se | se == nullPtr = fail "undefined sexp"
pdsexp se = liftM SExp $ FC.newForeignPtr se $ gcry_sexp_release se

wmq :: MQ any -> (Ptr () -> IO a) -> IO a
wmq (MQ fp) c = withForeignPtr fp (c . castPtr)

pci :: Ptr CUInt -> IO Int
pci = fmap fromIntegral . peek

e2ci :: Enum a => a -> CInt
e2ci = fromIntegral . fromEnum

e2cu :: Enum a => a -> CUInt
e2cu = fromIntegral . fromEnum

cu2i :: CUInt -> Int
cu2i = fromIntegral

wBuf :: ByteString -> ((Ptr a, CUInt) -> IO b) -> IO b
wBuf bs comp = unsafeUseAsCStringLen bs $ \(p,c) -> comp (castPtr p, fromIntegral c)

cIntConv :: Int -> CUInt
cIntConv = fromIntegral

withCStringLenIntConv :: String -> ((Ptr CChar, CUInt) -> IO a) -> IO a
withCStringLenIntConv str comp = withCStringLen str $ \(p,l) -> comp (p, fromIntegral l)

hexBS :: ByteString -> ByteString
hexBS = pack . Prelude.map (toEnum . fromEnum) . Prelude.concatMap sh . unpack
    where sh d = case showHex d "" of
                   [c]  -> ['0',c]
                   xs   -> xs
wZero c = c 0
wNull c = c nullPtr

i2o :: CInt -> Ordering
i2o c = c `compare` 0


eh :: CUInt -> IO ()
eh 0 = return ()
eh x = fail $ show $ Err x
