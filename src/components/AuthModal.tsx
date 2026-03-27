import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Mail, Lock, Loader2, Chrome, Phone, User, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { RecaptchaVerifier, ConfirmationResult } from "firebase/auth";
import { auth } from "@/lib/firebase";

declare global {
  interface Window {
    recaptchaVerifier: any;
  }
}

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function AuthModal({ isOpen, onClose }: AuthModalProps) {
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [authMethod, setAuthMethod] = useState<'email' | 'phone'>('email');
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  
  // Phone Auth State
  const [phoneNumber, setPhoneNumber] = useState("");
  const [otp, setOtp] = useState("");
  const [showOtpInput, setShowOtpInput] = useState(false);
  const [confirmationResult, setConfirmationResult] = useState<ConfirmationResult | null>(null);

  const [isLoading, setIsLoading] = useState(false);
  const { signIn, signUp, signInWithGoogle, signInAnonymously, setUpRecaptcha } = useAuth();
  const { toast } = useToast();

  // Cleanup on close
  const handleClose = () => {
    setShowOtpInput(false);
    setPhoneNumber("");
    setOtp("");
    setEmail("");
    setPassword("");
    setConfirmationResult(null);
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    const { error } = mode === 'signin' 
      ? await signIn(email, password)
      : await signUp(email, password);

    if (error) {
      toast({
        title: mode === 'signin' ? "Sign In Failed" : "Sign Up Failed",
        description: error.message,
        variant: "destructive",
      });
    } else {
      toast({
        title: mode === 'signin' ? "Welcome back!" : "Account created!",
        description: mode === 'signup' ? "You're now signed in." : "You're now signed in.",
      });
      onClose();
      setEmail("");
      setPassword("");
    }
    
    setIsLoading(false);
  };

  const handleGoogleSignIn = async () => {
    setIsLoading(true);
    const { error } = await signInWithGoogle();
    if (error) {
      toast({
        title: "Google Sign In Failed",
        description: error.message,
        variant: "destructive",
      });
      setIsLoading(false);
    } else {
      handleClose();
    }
  };

  const handleAnonymousSignIn = async () => {
    setIsLoading(true);
    const { error } = await signInAnonymously();
    if (error) {
      toast({
        title: "Guest Sign In Failed",
        description: error.message,
        variant: "destructive",
      });
    } else {
      toast({
        title: "Welcome Guest!",
        description: "You're now using PhishGuard anonymously.",
      });
      handleClose();
    }
    setIsLoading(false);
  };

  const handlePhoneSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!phoneNumber) return;
    
    setIsLoading(true);
    try {
      // Create Recaptcha verifier
      if (!window.recaptchaVerifier) {
        window.recaptchaVerifier = new RecaptchaVerifier(auth, 'recaptcha-container', {
          'size': 'invisible',
        });
      }

      // Format assuming user inputs standard number without country code for simplicity. 
      // Ideally provide a country code selector, but forcing +1 for demo.
      const formattedPhone = phoneNumber.startsWith('+') ? phoneNumber : `+1${phoneNumber}`;
      
      const result = await setUpRecaptcha(formattedPhone, window.recaptchaVerifier);
      
      if ('error' in result) {
        throw result.error;
      }

      setConfirmationResult(result);
      setShowOtpInput(true);
      toast({
        title: "Code Sent",
        description: `An SMS code was sent to ${formattedPhone}`,
      });
    } catch (error: any) {
      toast({
        title: "Failed to send code",
        description: error.message || "Please check the phone number format.",
        variant: "destructive",
      });
    }
    setIsLoading(false);
  };

  const handleOtpVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otp || !confirmationResult) return;
    
    setIsLoading(true);
    try {
      await confirmationResult.confirm(otp);
      toast({
        title: "Welcome!",
        description: "You have successfully signed in with your phone.",
      });
      handleClose();
    } catch (error: any) {
      toast({
        title: "Verification Failed",
        description: "The code you entered is incorrect.",
        variant: "destructive",
      });
    }
    setIsLoading(false);
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] px-[20px] pb-[20px] bg-background/80 backdrop-blur-sm"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          onClick={(e) => e.stopPropagation()}
          className="w-full max-w-md max-h-[85vh] overflow-y-auto bg-card border border-border rounded-2xl shadow-[0_0_50px_-12px_rgba(0,0,0,0.5)]"
        >
          {/* Invisible Recaptcha Container — hidden from view */}
          <div id="recaptcha-container" className="hidden"></div>

          {/* Header */}
          <div className="relative p-4 sm:p-6 bg-gradient-to-r from-primary/10 to-secondary/10 border-b border-border">
            <button
              onClick={handleClose}
              className="absolute top-4 right-4 p-1 rounded-full hover:bg-secondary/50 transition-colors"
            >
              <X className="w-5 h-5 text-muted-foreground" />
            </button>
            <h2 className="text-xl font-bold">
              {mode === 'signin' ? 'Welcome Back' : 'Create Account'}
            </h2>
            <p className="text-sm text-muted-foreground mt-1">
              Select your preferred way to authenticate.
            </p>
          </div>

          {/* Content */}
          <div className="p-4 sm:p-6 space-y-4 sm:space-y-5">
            {/* Quick Actions (Google & Guest) */}
            <div className="grid grid-cols-2 gap-3">
              <Button
                variant="outline"
                className="w-full h-11 gap-2"
                onClick={handleGoogleSignIn}
                disabled={isLoading}
              >
                <Chrome className="w-4 h-4" />
                Google
              </Button>
              <Button
                variant="outline"
                className="w-full h-11 gap-2 border-primary/20 hover:bg-primary/10 text-primary"
                onClick={handleAnonymousSignIn}
                disabled={isLoading}
              >
                <User className="w-4 h-4" />
                Guest
              </Button>
            </div>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t border-border" />
              </div>
              <div className="relative flex justify-center text-xs">
                <span className="bg-card px-2 text-muted-foreground">or login via</span>
              </div>
            </div>

            {/* Auth Method Tabs */}
            <div className="flex p-1 bg-secondary/30 rounded-lg">
              <button
                type="button"
                className={cn("flex-1 py-1.5 text-sm font-medium rounded-md transition-all", 
                  authMethod === 'email' ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground")}
                onClick={() => setAuthMethod('email')}
              >
                Email
              </button>
              <button
                type="button"
                className={cn("flex-1 py-1.5 text-sm font-medium rounded-md transition-all", 
                  authMethod === 'phone' ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground")}
                onClick={() => setAuthMethod('phone')}
              >
                Phone
              </button>
            </div>

            {/* Email Form */}
            {authMethod === 'email' && (
              <form onSubmit={handleSubmit} className="space-y-4 animate-in fade-in slide-in-from-bottom-2">
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="you@example.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="pl-10"
                      required
                      disabled={isLoading}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="password"
                      type="password"
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="pl-10"
                      required
                      minLength={6}
                      disabled={isLoading}
                    />
                  </div>
                </div>

                <Button type="submit" className="w-full h-11 bg-primary text-primary-foreground hover:bg-primary/90 glow-primary" disabled={isLoading}>
                  {isLoading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    mode === 'signin' ? 'Sign In' : 'Create Account'
                  )}
                </Button>
              </form>
            )}

            {/* Phone Form */}
            {authMethod === 'phone' && !showOtpInput && (
              <form onSubmit={handlePhoneSubmit} className="space-y-4 animate-in fade-in slide-in-from-bottom-2">
                <div className="space-y-2">
                  <Label htmlFor="phone">Phone Number</Label>
                  <div className="relative">
                    <Phone className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="phone"
                      type="tel"
                      placeholder="1234567890 (no +1 needed)"
                      value={phoneNumber}
                      onChange={(e) => setPhoneNumber(e.target.value)}
                      className="pl-10"
                      required
                      disabled={isLoading}
                    />
                  </div>
                </div>
                <Button type="submit" className="w-full h-11 bg-primary text-primary-foreground hover:bg-primary/90 glow-primary" disabled={isLoading}>
                  {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Send Verification Code'}
                </Button>
              </form>
            )}

            {/* OTP Form */}
            {authMethod === 'phone' && showOtpInput && (
              <form onSubmit={handleOtpVerify} className="space-y-4 animate-in fade-in slide-in-from-right-4">
                <div className="space-y-2">
                  <Label htmlFor="otp">Verification Code</Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-primary" />
                    <Input
                      id="otp"
                      type="text"
                      placeholder="123456"
                      value={otp}
                      onChange={(e) => setOtp(e.target.value)}
                      className="pl-10 text-center tracking-widest font-mono text-lg border-primary/50"
                      required
                      disabled={isLoading}
                      maxLength={6}
                    />
                  </div>
                  <button 
                    type="button" 
                    onClick={() => setShowOtpInput(false)}
                    className="text-xs flex items-center gap-1 text-muted-foreground hover:text-foreground mt-2"
                  >
                    ← Back to edit number
                  </button>
                </div>
                <Button type="submit" className="w-full h-11 bg-primary text-primary-foreground hover:bg-primary/90 glow-primary" disabled={isLoading}>
                  {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Verify Code'}
                </Button>
              </form>
            )}

            {/* Toggle Mode */}
            <p className="text-center text-sm text-muted-foreground">
              {mode === 'signin' ? (
                <>
                  Don't have an account?{' '}
                  <button
                    onClick={() => setMode('signup')}
                    className="text-primary hover:underline font-medium"
                  >
                    Sign up
                  </button>
                </>
              ) : (
                <>
                  Already have an account?{' '}
                  <button
                    onClick={() => setMode('signin')}
                    className="text-primary hover:underline font-medium"
                  >
                    Sign in
                  </button>
                </>
              )}
            </p>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
