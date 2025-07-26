plugins {
    `java-library`
}

dependencies {
    compileOnly(Libs.JavaxServlet.javax_servlet_api)
    implementation(Libs.JavaxMail.mail)
    implementation(Libs.CommonsCodec.commons_codec)
    implementation(Libs.CommonsLang.commons_lang)
}
