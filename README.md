# VerifyStoreReceiptiOS
Rick Maddy, Matthew Stevens, Ruotger Skupin, Apple, Dave Carlton, Fraser Hess, anlumo, yene, David Keegan, Alessandro Segala.

These files are based off of the [roddi/ValidateStoreReceipt](https://github.com/roddi/ValidateStoreReceipt) project.

At the end of October 2010 Apple announced the App Store for Mac. The App Store will put a receipt into your app bundle, but 
won't implement any copy protection scheme. For details see [Validating App Store Receipts](https://developer.apple.com/devcenter/mac/documents/validating.html) (Developer membership needed).

Once the iOS 7 NDA is lifted, a link to the iOS version can be added.

Unfortunately this document doesn't tell you how to process this receipt in detail, quote:

    The payload of the PKCS7 container is encoded using ASN.1, as described by ITU-T X.690.

This validator parses and validates the payload and the PKCS7 container itself. 

Thanks to Matthew Stevens for coming up with the parser code. Thanks to Dave Carlton for polishing it a bit. Thanks to Fraser Hess for more polish and correcting my non-native English. Thanks to anlumo for the certificate checking code. Thanks to Alessandro Segala for the In-App purchasing code.

Missing from this project: 

- Apple's root certificate. This may be obtained from http://www.apple.com/certificateauthority/
- Any measures to make your app cracker proof.

## Installation

If you have an app that is more or less ready for the App Store, I think you will be able figure it out. Important is that you link with the dependencies listed in validatereceipt.m.

## Using It

This class depends on OpenSSL being statically linked into your project. Please see https://github.com/x2on/OpenSSL-for-iPhone for one approach to getting that done.

Be aware that there will be people trying to crack your app. So cover your tracks. I won't go into details but Blocks and Grand Central Dispatch seem to be good tools for that.

## License

 Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 
 Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 
 Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in
 the documentation and/or other materials provided with the distribution.
 
 Neither the name of the copyright holders nor the names of its contributors may be used to endorse or promote products derived 
 from this software without specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
 BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
 OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
