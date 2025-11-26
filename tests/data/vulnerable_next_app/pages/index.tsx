import React from 'react';
import { useRouter } from 'next/router';

export default function VulnerablePage() {
  const router = useRouter();
  const { query } = router;
  
  // Vulnerability 1: XSS via dangerouslySetInnerHTML
  const userContent = "<img src=x onerror=alert(1)>";

  return (
    <div>
      <h1>Welcome to the Vulnerable App</h1>
      
      {/* XSS Vulnerability */}
      <div dangerouslySetInnerHTML={{ __html: userContent }} />
      
      {/* Vulnerability 2: Reflected XSS from query param */}
      <div>
        Search results for: {query.q}
      </div>
    </div>
  );
}

// Vulnerability 3: SSRF in getServerSideProps (simulated)
export async function getServerSideProps(context) {
  const { url } = context.query;
  if (url) {
    // In a real app this would be fetch(url)
    console.log("Fetching arbitrary URL:", url);
  }
  return { props: {} };
}
