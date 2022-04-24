import java.security.spec.{RSAPrivateKeySpec, RSAPublicKeySpec}
import java.security.{KeyFactory, PrivateKey, PublicKey}
import scala.util.Random

object Rsa {
  case class Private(privateKey: BigInt, modulus: BigInt) {
    def encrypt(message: Array[Byte]): Array[Byte] = BigInt(message).modPow(privateKey, modulus).toByteArray

    def decrypt(message: Array[Byte]): Array[Byte] = BigInt(message).modPow(privateKey, modulus).toByteArray
  }

  case class Public(publicKey: BigInt, modulus: BigInt) {
    def encrypt(message: Array[Byte]): Array[Byte] = BigInt(message).modPow(publicKey, modulus).toByteArray

    def decrypt(message: Array[Byte]): Array[Byte] = BigInt(message).modPow(publicKey, modulus).toByteArray
  }

  def generateKeyPair(rng: Random, keySize: Int = 1024): (Private, Public) = {
    val p = BigInt.probablePrime(keySize / 2, rng)
    val q = BigInt.probablePrime(keySize / 2, rng)

    val modulus: BigInt = p * q
    val phi: BigInt = (p - 1) * (q - 1)

    val publicKey: BigInt = BigInt(65537)
    val privateKey: BigInt = publicKey.modInverse(phi)

    (Private(privateKey, modulus), Public(publicKey, modulus))
  }

  def time[A](f: => A): A = {
    import java.time.{Duration, Instant}
    val t0 = Instant.now()
    val a = f
    val t1 = Instant.now()
    val duration = Duration.between(t0, t1)
    println(s"Elapsed: $duration")
    a
  }

  def main(args: Array[String]): Unit = {
    val random = Random()
    val message = "Hello World!".getBytes()
    val (privKey, pubKey) = generateKeyPair(random)

    val cipherText = privKey.encrypt(message)
    val plainText = pubKey.decrypt(cipherText)
    println(cipherText.mkString("<<", ", ", ">>"))
    println(plainText.mkString("<<", ", ", ">>"))
    println(String(plainText))
  }
}