-- ProductCode / ProductRole: portal B2B empleadores (separado de MEUDOC_PRO / especialistas)
ALTER TYPE "ProductCode" ADD VALUE 'MEUDOC_EMPLOYER';
ALTER TYPE "ProductRole" ADD VALUE 'EMPLOYER_ADMIN';
ALTER TYPE "ProductRole" ADD VALUE 'EMPLOYER_BILLING';
