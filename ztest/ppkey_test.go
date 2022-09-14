package ztest

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

func TestGenerateKey(t *testing.T) {

	// 1。使用 ECDSA 生成私钥
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed GenerateKey with %s.", err)
	}
	// 2.crypto.FromECDSA(private key) 转换成二进制数据
	fmt.Println("========================== 🔒Private key start===============================")
	fmt.Println("private key with 0x:", hexutil.Encode(crypto.FromECDSA(key)))
	fmt.Println("private key without 0x:", hex.EncodeToString(crypto.FromECDSA(key)))
	fmt.Println("========================== 🔒Private key end=================================")
	fmt.Println()

	//3.根据椭圆曲线数字签名算法，获取public key
	fmt.Println("========================== 🔐Public key start================================")
	fmt.Println("public key have 0x : ", hexutil.Encode(crypto.FromECDSAPub(&key.PublicKey)))
	fmt.Println("public key no 0x : ", hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey)))
	fmt.Println("========================== 🔐Public key end==================================")
	fmt.Println()
	fmt.Println()
	fmt.Println()

	////由私钥字符串转换私钥
	//acc1Key, _ := crypto.HexToECDSA(hex.EncodeToString(crypto.FromECDSA(key)))
	////fmt.Println("Gen private key by priKey String, 🔐:", hexutil.Encode(acc1Key.D))
	//fmt.Println("Gen private key by priKey String, 🔓:", acc1Key, key)

	//4.根据 公钥 生成 地址
	address := crypto.PubkeyToAddress(key.PublicKey)
	fmt.Println("========================== 📪address start===============================")
	fmt.Println("Gen address from public key:", address.String())
	fmt.Println("========================== 📪address end===============================")
	fmt.Println()
	// 以上是 通过ECDSA生成公私、通过公钥生成 地址

	//待验证地址（以太坊）
	var testAddrHex = "970e8128ab834e8eac17ab8e3812f010678cf791"
	//和地址配对的私钥,后面用来签名
	var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"
	//1.根据私钥，创建keypair（公私钥）
	keypair, _ := crypto.HexToECDSA(testPrivHex)
	//2.转成0x地址
	addrtest := common.HexToAddress(testAddrHex)
	//3.发送的数据，进行hash
	msg := crypto.Keccak256([]byte("周末去刘哥家吃饭"))
	fmt.Println("========================== 👇 hash 后的数据 begin==========================")
	fmt.Println("msg:", hexutil.Encode(msg))
	fmt.Println("========================== 👆 hash 后的数据 end==========================")
	fmt.Println()
	//4.签名（k1算法进行签名）（使用了私钥）
	sig, err := crypto.Sign(msg, keypair) //进行签名

	fmt.Println("========================== 👇签名后的数据 begin==========================")
	fmt.Println("msg:", hexutil.Encode(sig))
	fmt.Println("========================== 👆签名后的数据 end==========================")
	fmt.Println()
	//5.验证重点，通过 ECC Ecrecover 方法进行恢复公钥
	recoveredPub, err := crypto.Ecrecover(msg, sig)

	pubKey, _ := crypto.UnmarshalPubkey(recoveredPub)
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)

	//使用 SigToPub 函数，根据签名和公开信息获取公钥 （本质也是使用Ecrecover）
	recoveredPub2, _ := crypto.SigToPub(msg, sig)
	recoveredAddr2 := crypto.PubkeyToAddress(*recoveredPub2)

	fmt.Println("待验证地址： ", addrtest.String())
	fmt.Println("使用 Ecrecover 恢复的地址信息：", recoveredAddr.String())
	fmt.Println("使用 SigToPub 恢复的地址信息：", recoveredAddr2.String())
}
